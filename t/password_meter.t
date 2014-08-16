#!/usr/bin/env perl
use strict;
use warnings;
use lib '../lib';
use Test::More;
use Data::Password::Meter;

# Check with utf8

my $pwd = Data::Password::Meter->new;

ok(!$pwd->strong(''), 'Too weak');
is($pwd->errstr, 'There is no password given', 'No password');
is($pwd->err, 1, 'Error code');

ok(!$pwd->strong("Pass\tword"), 'Too weak');
is($pwd->errstr, 'Passwords are not allowed to contain control sequences', 'control sequences');
is($pwd->err, 2, 'Error code');


ok(!$pwd->strong("bbbbbbbbb"), 'Too weak');
is($pwd->errstr, 'Passwords are not allowed to consist of repeating characters only', 'repeating characters');
is($pwd->err, 3, 'Error code');


# Single failures
ok(!$pwd->strong("a!c"), 'Too weak');
is($pwd->score, 9, 'Score');
is($pwd->errstr, 'The password is too short',
   'too short');
is($pwd->err, 4, 'Error code');


ok(!$pwd->strong("abcdefghij"), 'Too weak');
is($pwd->score, 17, 'Score');
is($pwd->errstr, 'The password should contain special characters',
   'special characters');
is($pwd->err, 5, 'Error code');


ok(!$pwd->strong("abcd!fghij"), 'Too weak');
is($pwd->score, 24, 'Score');
is($pwd->errstr, 'The password should contain combinations of letters, numbers and special characters',
   'combinations and special characters');
is($pwd->err, 6, 'Error code');

# Complex failures
ok(!$pwd->strong("abc"), 'Too weak');
is($pwd->score, 4, 'Score');
is($pwd->errstr, 'The password is too short and should contain special characters',
   'too short and no special characters');
is($pwd->err, 7, 'Error code');

# Fine
ok($pwd->strong("aA!.+!.+"), 'Too weak');
is($pwd->score, 32, 'Score');

ok(!$pwd->strong("aaaaaaaa!"), 'Too weak');
is($pwd->score, 22, 'Score');
is($pwd->errstr, 'The password should contain combinations of letters, numbers and special characters',
   'combinations and special characters');
is($pwd->err, 6, 'Error code');


ok(!$pwd->strong("aAaAaAaA"), 'Too weak');
is($pwd->score, 18, 'Score');
is($pwd->errstr, 'The password is too short and should contain special characters',
   'too short and no special characters');
is($pwd->err, 7, 'Error code');

is($pwd->threshold, 25, 'Threshold');

$pwd = Data::Password::Meter->new(33);

is($pwd->threshold, 33, 'Threshold');

# Not fine
ok(!$pwd->strong("aA!.+!.+"), 'Too weak');
is($pwd->score, 32, 'Score');
is($pwd->errstr, 'The password is too short and should contain combinations of letters, numbers and special characters',
   'too short and no special characters');
is($pwd->err, 8, 'Error code');

# Fine
$pwd->threshold(25);
ok($pwd->strong("aA!.+!.+"), 'Too weak');
is($pwd->score, 32, 'Score');


done_testing;
