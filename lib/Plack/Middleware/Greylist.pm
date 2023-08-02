package Plack::Middleware::Greylist;

# ABSTRACT: throttle requests with different rates based on net blocks

# RECOMMEND PREREQ: Cache::FastMmap
# RECOMMEND PREREQ: Ref::Util::XS

use v5.12;
use warnings;

use parent qw( Plack::Middleware );

use HTTP::Status qw/ HTTP_FORBIDDEN HTTP_TOO_MANY_REQUESTS /;
use List::Util   1.29 qw/ pairs /;
use Module::Load qw/ load /;
use Net::IP::Match::Trie;
use Plack::Util;
use Plack::Util::Accessor qw/ default_rate rules cache file _match greylist retry_after /;
use Ref::Util             qw/ is_plain_arrayref /;
use Time::Seconds         qw/ ONE_MINUTE /;

our $VERSION = 'v0.4.5';

=head1 SYNOPSIS

  use Plack::Builder;

  builder {

    enable "Greylist",
      file         => sprintf('/run/user/%u/greylist', $>), # cache file
      default_rate => 250,
      greylist     => {
          '192.168.0.0/24' => 'whitelist',
          '172.16.1.0/25'  => [ 100, 'netblock' ],
      };

  }

=head1 DESCRIPTION

This middleware will apply rate limiting to requests, depending on the requestor netblock.

Hosts that exceed their configured per-minute request limit will be rejected with HTTP 429 errors.

=head2 Log Messages

Rejections will be logged with a message of the form

    Rate limiting $ip after $hits/$rate for $netblock

for example,

    Rate limiting 172.16.0.10 after 225/250 for 172.16.0.0/24

Note that the C<$netblock> for the default rate is simply "default", e.g.

    Rate limiting 192.168.0.12 after 101/100 for default

This will allow you to use something like L<fail2ban> to block repeat offenders, since bad
robots are like houseflies that repeatedly bump against closed windows.

=attr default_rate

This is the default maximum number of hits per minute before requests are rejected, for any request not in the L</greylist>.

Omitting it will disable the global rate.

=attr retry_after

This sets the C<Retry-After> header value, in seconds. It defaults to 61 seconds, which is the minimum allowed value.

Note that this does not enforce that a client has waited that amount of time before making a new request, as long as the
number of hits per minute is within the allowed rate.

=attr greylist

This is a hash reference to the greylist configuration.

The keys are network blocks, and the values are an array reference of rates and the tracking type. (A string of space-
separated values can be used instead, to make it easier to directly use the configuration from something like
L<Config::General>.)

The rates are either the maximum number of requests per minute, or "whitelist" or "allowed" to not limit the network
block, or "blacklist" or "rejected" to always forbid a network block.

(The rate "-1" corresponds to "allowed", and the rate "0" corresponds to "rejected".)

A special rate code of "norobots" will reject all requests except for F</robots.txt>, which is allowed at a rate of 60
per minute.  This will allow you to block a robot but still allow the robot to access the robot rules that say it is
disallowed.

The tracking type defaults to "ip", which applies limits to individual ips. You can also use "netblock" to apply the
limits to all hosts in that network block, or use a name so that limits are applied to all hosts in network blocks
with that name.

For example:

    {
        '127.0.0.1/32' => 'whitelist',

        '192.168.1.0/24' => 'blacklist',

        '192.168.2.0/24' => [ 100, 'ip' ],

        '192.168.3.0/24' => [  60, 'netblock' ],

        # All requests from these blocks will limited collectively

        '10.0.0.0/16'    => [  60, 'group1' ],
        '172.16.0.0/16'  => [  60, 'group1' ],
    }

Note: the network blocks shown above are examples only.

The limit may be larger than L</default_rate>, to allow hosts to exceed the default limit.

=attr file

This is the path of the throttle count file used by the L</cache>.

It is required unless you are defining your own L</cache>.

=attr cache

This is a code reference to a function that increments the cache counter for a key (usually the IP address or net
block).

If you customise this, then you need to ensure that the counter resets or expires counts after a set period of time,
e.g. one minute.  If you use a different time interval, then you may need to adjust the L</retry_after> time.

=head1 KNOWN ISSUES

This does not try and enforce any consistency or block overlapping netblocks.  It trusts L<Net::IP::Match::Trie> to
handle any overlapping or conflicting network ranges, or to specify exceptions for larger blocks.

When configuring the L</greylist> netblocks from a configuration file using L<Config::General>, duplicate netblocks may
be merged in unexpected ways, for example

    10.0.0.0/16   60 group-1

    ...

    10.0.0.0/16  120 group-2


may be merged as something like

    '10.0.0.0/16' => [ '60 group-1', '120 group-2' ],

Some search engine robots may not respect HTTP 429 responses, and will treat these as errors. You may want to make an
exception for trusted networks that gives them a higher rate than the default.

This does not enforce consistent rates for named blocks. For example, if you specified

    '10.0.0.0/16'    => [  60, 'named-group' ],
    '172.16.0.0/16'  => [ 100, 'named-group' ],

Requests from both netblocks would be counted together, but requests from 10./16 netblock would be rejected after 60
requests. This is probably not something that you want.

=cut

sub prepare_app {
    my ($self) = @_;

    $self->default_rate(-1) unless defined $self->default_rate;

    die "default_rate must be a positive integer" unless $self->default_rate =~ /^[1-9][0-9]*$/;

    $self->retry_after( ONE_MINUTE + 1 ) unless defined $self->retry_after;
    die "retry_after must be a positive integer greater than ${ \ONE_MINUTE} seconds"
      unless $self->retry_after =~ /^[1-9][0-9]*$/ && $self->retry_after > ONE_MINUTE;

    unless ( $self->cache ) {

        my $file = $self->file // die "No cache was set";

        load Cache::FastMmap;

        my $cache = Cache::FastMmap->new(
            share_file  => "$file",
            init_file   => 1,
            serializer  => '',
            expire_time => ONE_MINUTE,
        );

        $self->cache(
            sub {
                my ($ip) = @_;
                return $cache->get_and_set(
                    $ip,
                    sub {
                        my ( $key, $count, $opts ) = @_;
                        $count //= 0;
                        return ( $count + 1, { expire_on => $opts->{expire_on} } );
                    }
                );
            }
        );

    }

    my $match = Net::IP::Match::Trie->new;

    $self->_match( sub { return $match->match_ip(@_) } );

    my @blocks;

    if ( my $greylist = $self->greylist ) {
        push @blocks, ( %{ $greylist } );
    }

    $self->rules( my $rules = {} );

    my %codes = ( whitelist => -1, allowed => -1, blacklist => 0, rejected => 0, norobots => 0 );
    my %types = ( ip => '', netblock => 1 );

    for my $line ( pairs @blocks ) {

        my ( $block, $rule ) = @{$line};
        $rule = [ split /\s+/, $rule ] unless is_plain_arrayref($rule);

        my ( $rate, $type ) = @{ $rule };

        $type //= "ip";
        my $mask = $types{$type} // $type;
        $mask = $block if $mask eq "1";

        $rate //= "rejected";
        if (exists $codes{$rate}) {
            $mask = $rate if $mask eq "";
            $rate = $codes{$rate};
        }

        $rules->{$block} = [ $rate, $mask ];
        $match->add( $block => [$block] );
    }

}

sub call {
    my ( $self, $env ) = @_;

    my $ip   = $env->{REMOTE_ADDR};
    my $name = $self->_match->($ip);
    my $rule = $name ? $self->rules->{$name} : [ $self->default_rate ];

    my $rate = $rule->[0];

    if ( $rate == 0 && $rule->[1] && $rule->[1] eq "norobots" ) {
        if ( $env->{PATH_INFO} eq "/robots.txt" ) {
            $rate = ONE_MINUTE;    # one request/second
        }
    }

    if ( $rate >= 0 ) {

        my $limit = $rate == 0;

        my ($hits) = $self->cache->( $rule->[1] || $ip );
        $limit = $hits > $rate ? $hits : 0;

        if ($limit) {

            my $block = $name || "default";
            my $msg = "Rate limiting ${ip} after ${limit}/${rate} for ${block}";

            if ( my $log = $env->{'psgix.logger'} ) {
                $log->( { message => $msg, level => 'warn' } );
            }
            else {
                $env->{'psgi.errors'}->print($msg);
            }

            if ( $rate == 0 ) {

                return [ HTTP_FORBIDDEN, [], ["Forbbidden"] ];

            }
            else {

                return [
                    HTTP_TOO_MANY_REQUESTS,
                    [
                        "Retry-After" => $self->retry_after,
                    ],
                    ["Too Many Requests"]
                ];

            }
        }

    }

    return $self->app->($env);
}

=head1 SUPPORT FOR OLDER PERL VERSIONS

This module requires Perl v5.12 or later.

Future releases may only support Perl versions released in the last ten years

=head1 append:AUTHOR

The initial development of this module was sponsored by Science Photo
Library L<https://www.sciencephoto.com>.

=cut

1;
