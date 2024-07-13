use v5.20;
use warnings;

use Test2::V0;
use Test2::Tools::Compare;

use HTTP::Request::Common;
use HTTP::Status qw/ :constants status_message /;
use Path::Tiny;
use Plack::Builder;
use Plack::Response;
use Plack::Test;
use Plack::Middleware::ReverseProxy;

use experimental qw/ signatures /;

my $file = Path::Tiny->tempfile;

my %greylist = ();

my @logs;
my @calls;

my $Timeout = 2;

my $handler = builder {

    # Capture log messages
    enable sub($app) {
        sub($env) {
            $env->{'psgix.logger'} = sub {
                push @logs, $_[0];
            };
            return $app->($env);
        };
    };

    # Trust the "X-Forwarded-For" header
    enable "ReverseProxy";

    enable "Greylist",
      default_rate => 5,
      cache_config => {
        init_file      => 1,
        unlink_on_exit => 1,
        expire_time    => 30,
        share_file     => $file,
      },
      greylist => \%greylist;

    enable sub($app) {
        sub($env) {
            if ( my $add = $env->{"psgix.greylist.add_rule"} ) {
                my $ip = $env->{REMOTE_ADDR};
                $add->( $ip, 0, "ip", time + $Timeout );
                if ( my $log = $env->{'psgix.logger'} ) {
                    $log->( { message => "Blocking $ip for $Timeout seconds", level => "info" } );
                }
            }
            return $app->($env);
        };
    };

    sub($env) {
        my $res = Plack::Response->new( HTTP_OK, [ 'Content-Type' => 'text/plain' ], [ status_message(HTTP_OK) ] );
        return $res->finalize;
    }
};

subtest "rate limiting" => sub {

    @logs = ();

    my $ip = "172.16.0.1";

    test_psgi
      app    => $handler,
      client => sub($cb) {

        {
            my $req = HEAD "/", "X-Forwarded-For" => $ip;
            my $res = $cb->($req);
            is $res->code, HTTP_OK, "request ok";
        }

        {
            my $req = HEAD "/", "X-Forwarded-For" => $ip;
            my $res = $cb->($req);
            is $res->code, HTTP_FORBIDDEN, "request blocked due to dynamic rule";
        }

        # This is allowed despire the timeout
        {
            my $req = HEAD "/", "X-Forwarded-For" => "172.16.1.2";
            my $res = $cb->($req);
            is $res->code, HTTP_OK, "request ok after expiration";
        }

        sleep 1 + $Timeout;

        {
            my $req = HEAD "/", "X-Forwarded-For" => $ip;
            my $res = $cb->($req);
            is $res->code, HTTP_OK, "request ok after expiration";
        }

        {
            my $req = HEAD "/", "X-Forwarded-For" => $ip;
            my $res = $cb->($req);
            is $res->code, HTTP_FORBIDDEN, "request blocked due to dynamic rule";
        }

      };

    is \@logs,
      [
        {
            level   => "info",
            message => "Blocking ${ip} for ${Timeout} seconds",
        },
        {
            level   => "warn",
            message => "Rate limiting ${ip} after 2/0 for ${ip}",
        },
        {
            level   => "info",
            message => "Blocking 172.16.1.2 for ${Timeout} seconds",
        },
        {
            level   => "info",
            message => "Blocking ${ip} for ${Timeout} seconds",
        },
        {
            level   => "warn",
            message => "Rate limiting ${ip} after 3/0 for ${ip}",
        },
      ],
      "logs";

};

done_testing;
