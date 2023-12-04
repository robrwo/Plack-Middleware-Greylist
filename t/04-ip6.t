use v5.12;
use warnings;

use Test2::V0;

use HTTP::Request::Common;
use HTTP::Status qw/ :constants status_message /;
use Path::Tiny;
use Plack::Builder;
use Plack::Response;
use Plack::Test;
use Plack::Middleware::ReverseProxy;

my $file = Path::Tiny->tempfile;

my %greylist = (
    "2001:67c:1220::/32"   => [ 5,  "first" ],
    "2001:67c:1220:f565::/64" => [ 6, "second" ],
);

my @logs;

my $handler = builder {

    # Capture log messages
    enable sub {
        my $app = shift;
        sub {
            my $env = shift;
            $env->{'psgix.logger'} = sub {
                push @logs, $_[0];
            };
            return $app->($env);
        };
    };

    # Trust the "X-Forwarded-For" header
    enable "ReverseProxy";

    enable "Greylist",
      default_rate => 10,
      file         => $file,
      init_file    => 1,
      greylist     => \%greylist;

    sub {
        my ($env) = @_;
        my $res = Plack::Response->new( HTTP_OK, [ 'Content-Type' => 'text/plain' ], [ status_message(HTTP_OK) ] );
        return $res->finalize;
    }
};

subtest "rate limiting" => sub {

    @logs = ();

    test_psgi
      app    => $handler,
      client => sub {
        my $cb = shift;

        for my $suff ( 1 .. 5 ) {
            my $req = HEAD "/", "X-Forwarded-For" => "2001:67c:1220::1";
            my $res = $cb->($req);
            is $res->code, HTTP_OK, "request ok";
        }

        my $req = HEAD "/", "X-Forwarded-For" => "2001:67c:1220::1";
        my $res = $cb->($req);
        is $res->code, HTTP_TOO_MANY_REQUESTS, "too many requests";

        is \@logs, [ { level => "warn", message => "Rate limiting 2001:67c:1220::1 after 6/5 for 2001:67c:1220::/32" } ], "logs";

      };

};

subtest "rate limiting" => sub {

    @logs = ();

    test_psgi
      app    => $handler,
      client => sub {
        my $cb = shift;

        for my $suff ( 1 .. 6 ) {
            my $req = HEAD "/", "X-Forwarded-For" => "2001:67c:1220:f565::1";
            my $res = $cb->($req);
            is $res->code, HTTP_OK, "request ok";
        }

        my $req = HEAD "/", "X-Forwarded-For" => "2001:67c:1220:f565::1";
        my $res = $cb->($req);
        is $res->code, HTTP_TOO_MANY_REQUESTS, "too many requests";

        is \@logs, [ { level => "warn", message => "Rate limiting 2001:67c:1220:f565::1 after 7/6 for 2001:67c:1220:f565::/64" } ], "logs";

      };

};

subtest "default" => sub {

    @logs = ();

    test_psgi
      app    => $handler,
      client => sub {
        my $cb = shift;

        my $req = HEAD "/", "X-Forwarded-For" => "2002:67c:1220:f565::1235";

        for ( 1 .. 10 ) {
            my $res = $cb->($req);
            is $res->code, HTTP_OK, "request ok";
        }

        my $res = $cb->($req);
        is $res->code, HTTP_TOO_MANY_REQUESTS, "too many requests";

        is \@logs, [ { level => "warn", message => "Rate limiting 2002:67c:1220:f565::1235 after 11/10 for default" } ], "logs";

      };

};

done_testing;
