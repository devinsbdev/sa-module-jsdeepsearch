#!/usr/bin/perl

=head1 NAME

Mail::SpamAssassin::Plugin::DeepSearchJS - find and decode MIME octet-stream(s) of RFC-2822 message and check for nested javascript

=head1 SYNOPSIS

  #loadmekthx.pre
  loadplugin     Mail::SpamAssassin::Plugin::DeepSearchJS

  #local.cf
  full        DSJS_NESTED_SCRIPTBLOCK      eval:deepsearchjs()
  describe    DSJS_NESTED_SCRIPTBLOCK      Found nested <script> block(s)

=head1 DESCRIPTION

This module processes an entire raw, undecoded email message (a "full" message in SA terms) and allows
regex testing on the decoded textual data acquired from any "Content-Type:*/octet-stream" MIME parts. 
SpamAssassin doesn't take action on octet streams **NESTED WITHIN FIRST LEVEL ATTACHMENTS**  without 
otherwise manipulating the base Mail::SpamAssassin::Message::Node class. 

Example use case:
      
  ->  MSG file attachment in an incoming message contains an embedded HTM/HTML file attachment, which 
      itself contains obfuscated javascript (that won't do anything nice when opened in a user's browser).

Any part of the message containing viable JavaScript will have the "Content-Type:*/octet-stream" 
MIME header set.

The message structure, after initiating a parse() cycle, looks like this:

  Message object, also top-level node in Message::Node tree
     |
     +---> Message::Node for other parts in MIME structure
     |       |---> [ more Message::Node parts ... ]
     |       [ others ... ]
     |
     +---> Message::Metadata object to hold metadata

=head1 PUBLIC METHODS

=over 2

=cut

package Mail::SpamAssassin::Plugin::DeepSearchJS;

use Mail::SpamAssassin;
use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use File::Slurp qw( slurp );


use strict;
use warnings;
use re 'taint';

our @ISA = qw(Mail::SpamAssassin::Plugin);

# ---------------------------------------------------------------------------

=item new()

DeepSearchJS constructor - Creates a Mail::SpamAssassin::Plugin::DeepSearchJS object.  Takes a 
hash reference as a parameter.

=cut

sub new
{
    # `shift` does kinda like a ".pop(0)" on constructor params
    # we could also write these property declarations as
    # my ($class, $saobject) = @_; # to achieve same result
    my $class = shift;
    my $saobject = shift;

    # sa plugin class boilerplate;
    $class = ref($class) || $class;
    my $self = $class->SUPER::new($saobject);
    bless ($self, $class);

    # register eval functions declared below so they're available in local.cf rules
    $self->register_eval_rule('deepsearchjs');

    return $self;
}

# ---------------------------------------------------------------------------

=item deepsearchjs()

1. Find all octet-stream MIME parts given 'pristine_msg' scalar. 
2. Decode these parts to examine any text artifacts contained within.
3. Search for <script></script> tags, evidence of vbscript or powershell, etc..

Default args passed from "eval:" rule line in local.cf:

  ->  $self: Uh, "self"-explanatory?
  ->  $pms:  The default Mail::SpamAssassin::PerMessageStatus object containing info about the message.
  ->  $pristine: The "full", undecoded message object passed in by eval:deepsearchjs()

=cut

sub deepsearchjs
{
    my ( $self, $pms, $pristine ) = @_; # argv

    my $sa = Mail::SpamAssassin->new(); # sa worker; utilize parse() method
    my $msg = $sa->parse( $pristine ); # create Mail::SpamAssassin::Message object using pristine message input from eval
    my $sa_score = 0;

    # find_parts() method splits on MIME boundary; MIME parts with "Content-Type:" 
    # matching specified regex pattern group [qr/(EXPR)/] will go into @msg_parts array
    my @msg_parts = $msg->find_parts( qr(.*octet.*), 1, 1 ); # 2nd arg = 1 = return leaves only; #3rd arg = 1 = recursive (default)
    my $mime_count = scalar(@msg_parts); # return arraylength
    
    info("Found $mime_count MIME parts with 'Content-Type:*/octet-stream'.");

    foreach my $msg_part ( @msg_parts )
    {
        # Mail::SpamAssassin::Message::decode() method automatically determines byte 
        # and content transfer encoding schemes, then converts seamlessly between encoded and 
        # plain-text data. If you have time to kill, you can instead use "Encoding" + 
        # "MIME::Base64" perl modules to do this manually. Worked as expected when I tested it.
        my $decoded_str = scalar($msg_part->decode());

        # check decoded message text for script blocks
        if ( $decoded_str =~ qr/<script.*\<\/script\>/ )
        {
            $sa_score += 8.00;
            info("Found JAVASCRIPT!");
    	  }
        if ( $decoded_str =~ qr/vbscript/ or $decoded_str =~ qr/WScript\.Shell/ )
        {
            $sa_score += 8.33;
            info("Found VBSCRIPT!");
        }
        if ( $decoded_str =~ qr/\-[Ee^]{1,2}[NnCcOoDdEeMmAa^]+ [A-Za-z0-9+\/\=]{5,}/ or $decoded_str =~ qr/powershell\.exe/ )
        {
            $sa_score += 8.66;
            info("Found POWERSHELL!");
        }

        if ( $sa_score > 0 )
        {
            $pms->got_hit("DSJS_NESTED_SCRIPTBLOCK", "ATTACHMENT: ", score => $sa_score);
            return 1;
        }
    }

    $msg->finish();
    return 0;
}

# ---------------------------------------------------------------------------

=head1 NOTES

hi, nice to see you.

=cut

=head1 COPYRIGHT

Copyright 2022 Devin Imirie || Smithbucklin

=cut

1;