package Mail::GPG::Result;

# $Id: Result.pm,v 1.4 2004/06/15 20:55:47 joern Exp $

use strict;

sub get_is_encrypted		{ shift->{is_encrypted}			}
sub get_enc_ok			{ shift->{enc_ok}			}
sub get_enc_key_id		{ shift->{enc_key_id}			}
sub get_enc_mail		{ shift->{enc_mail}			}

sub get_is_signed		{ shift->{is_signed}			}
sub get_sign_ok			{ shift->{sign_ok}			}
sub get_sign_key_id		{ shift->{sign_key_id}			}
sub get_sign_mail		{ shift->{sign_mail}			}
sub get_sign_mail_aliases	{ shift->{sign_mail_aliases}		}

sub get_gpg_stdout		{ shift->{gpg_stdout}			}
sub get_gpg_stderr		{ shift->{gpg_stderr}			}
sub get_gpg_rc			{ shift->{gpg_rc}			}

sub new {
	my $class = shift;
	my %par = @_;
	my  ($enc_key_id, $enc_mail, $sign_key_id, $sign_mail) =
	@par{'enc_key_id','enc_mail','sign_key_id','sign_mail'};
	my  ($gpg_stdout, $gpg_stderr, $gpg_rc, $sign_ok, $enc_ok) =
	@par{'gpg_stdout','gpg_stderr','gpg_rc','sign_ok','enc_ok'};
	my  ($is_signed, $is_encrypted, $sign_mail_aliases) =
	@par{'is_signed','is_encrypted','sign_mail_aliases'};

	#-- by default extract attributes from gpg's stderr output
	if ( $gpg_stderr ) {
	    $is_signed   = ($$gpg_stderr =~ /signature made/i)||0
	    		   if !defined $is_signed;
	    $sign_ok     = ($$gpg_stderr =~ /good signature/i)||0
	    		   if !defined $sign_ok;
	    $sign_key_id = ($$gpg_stderr =~ /signature made.*?key.*?id (\w+)/i)[0]||""
	    		   if !defined $sign_key_id;
	    $sign_mail   = ($$gpg_stderr =~ /signature from "(.*?)"/i)[0]||""
	    		   if !defined $sign_mail;
	    $enc_key_id  = ($$gpg_stderr =~ /encrypted with.*?key.*?id (\w+)/i)[0]||""
	    		   if !defined $enc_key_id;
	    $enc_mail    = ($$gpg_stderr =~ /encrypted.*?\n.*?"(.*?)"/i)[0]||""
	    		   if !defined $enc_mail;

	    if ( !defined $sign_mail_aliases ) {
	        my @sign_mail_aliases = $$gpg_stderr =~ /^gpg:\s+aka\s+"(.*?)"/mg;
		$sign_mail_aliases = \@sign_mail_aliases;
	    }
	}

	#-- initialize reference attributes to prevent
	#-- dereferencing undef errors
	$gpg_stdout        = \"" if not defined $gpg_stdout;
	$gpg_stderr        = \"" if not defined $gpg_stderr;
	$sign_mail_aliases = []  if not defined $sign_mail_aliases;

	my $self = bless {
		enc_ok		  => $enc_ok,
		enc_key_id	  => $enc_key_id,
		enc_mail	  => decode($enc_mail),
		sign_ok		  => $sign_ok,
		sign_key_id	  => $sign_key_id,
		sign_mail	  => decode($sign_mail),
		gpg_stdout	  => $gpg_stdout,
		gpg_stderr	  => $gpg_stderr,
		gpg_rc		  => $gpg_rc,
		is_signed	  => $is_signed,
		is_encrypted	  => $is_encrypted,
		sign_mail_aliases => $sign_mail_aliases,
	}, $class;

	return $self;
}

sub decode {
	my ($str) = @_;
	return $str if not defined $str;
	$str =~ s/\\x(..)/chr(hex($1))/eg;
	return $str;
}

sub as_string {
	my $self = shift;
	my %par = @_;
	my ($no_stdout) = $par{'no_stdout'};

	my ($method, $string);
	foreach my $attr (qw (is_encrypted enc_ok enc_key_id enc_mail
			      is_signed sign_ok sign_key_id sign_mail
			      sign_mail_aliases
			      gpg_rc )) {
	    if ( $attr eq 'sign_mail_aliases' ) {
		foreach my $alias ( @{$self->get_sign_mail_aliases} ) {
		    $string .= sprintf ("%-16s: %s\n", "sign_mail_alias", $alias);
		}
	    } else {
		$method = "get_$attr";
		$string .= sprintf ("%-16s: %s\n", $attr, $self->$method() || '');
	    }
	}

	my $stdout = ${$self->get_gpg_stdout};
	my $stderr = ${$self->get_gpg_stderr};

	$stdout =~ s/\n/\n                  /g if $stdout;
	$stderr =~ s/\n/\n                  /g if $stderr;

	$string .= sprintf ("%-16s: %s\n", "gpg_stdout", $stdout || '')
		if not $no_stdout;
	$string .= sprintf ("%-16s: %s\n", "gpg_stderr", $stderr || '');

	return $string;
}

sub as_short_string {
	my $self = shift;

	my $string;

	if ( $self->get_is_encrypted ) {
		$string .= "ENC(".
			   $self->get_enc_mail.", ".
			   $self->get_enc_key_id.", ".
			   ($self->get_enc_ok?"OK":"NOK").
			   ") - ";
	} else {
		$string .= "NOENC - ";
	}

	if ( $self->get_is_signed ) {
		$string .= "SIGN(".
			   $self->get_sign_mail.", ".
			   $self->get_sign_key_id.", ".
			   ($self->get_sign_ok?"OK":"NOK").
			   ") - ";
	} else {
		$string .= "NOSIGN - ";
	}

	$string =~ s/ - $//;
	
	return $string;
}

1;

__END__


=head1 NAME

Mail::GPG::Result - Mail::GPG decryption and verification results

=head1 SYNOPSIS

  $result = $mg->verify (
    entity => $entity
  );
  
  ($decrypted_entity, $result) = $mg->decrypt (
    entity => $entity,
  );

  $long_string  = $result->as_string ( ... );
  $short_string = $result->as_short_string;

  $encrypted           = $result->get_is_encrypted;
  $decryption_ok       = $result->get_enc_ok;
  $encryption_key_id   = $result->get_enc_key_id;
  $encryption_mail     = $result->get_enc_mail;

  $signed              = $result->get_is_signed;
  $signature_ok        = $result->get_sign_ok;
  $signed_key          = $result->get_sign_key_id;
  $signed_mail         = $result->get_sign_mail;
  $signed_mail_aliases = $result->get_sign_mail_aliases;

  $stdout_sref         = $result->get_gpg_stdout;
  $stderr_sref         = $result->get_gpg_stderr;
  $gpg_exit_code       = $result->get_gpg_rc;

=head1 DESCRIPTION

This class encapsulates decryption and verification results
of Mail::GPG. You never create objects of this class yourself,
they're all returned by Mail::GPG.

=head1 ATTRIBUTES

This class mainly has a bunch of attributes which reflect the
result of a Mail::GPG operation. You can read these attributes
with B<get>_attribute.

=over 4

=item B<is_encrypted>

Indicates whether an entity was encrypted or not.

=item B<enc_ok>

Indicates whether decryption of an entity was successful or not.

=item B<enc_key_id>

The key ID of the sender who encrypted an entity.

=item B<enc_mail>

The mail address of the sender who encrypted an entity.

=item B<is_signed>

Indicates whether an entity was signed or not.

=item B<sign_ok>

Indicates whether the signature could be verified successfully or not.

=item B<sign_key_id>

The key ID of the sender who signed an entity.

=item B<sign_mail>

The primary mail address of the sender who signed an entity.

=item B<sign_mail_aliases>

A reference to a list of the signer's mail alias addresses.

=item B<gpg_stdout>

This is reference to a scalar containing gpg's STDOUT output.

=item B<gpg_stderr>

This is reference to a scalar containing gpg's STDERR output.

=item B<gpg_rc>

Exit code of the gpg program.

=back

=head1 METHODS

There are only two methods, both are for debugging purposes:

=head2 as_string

  $string = $result->as_string ( no_stdout => $no_stdout )

Returns a printable string version of the object.

=over 4

=item no_stdout

If this option is set, gpg's stdout is ommitted in the
string represenation.

=back

=head2 as_short_string

  $short_string = $result->as_short_string;
  
Returns a very short string representation, without any
gpg output, arranged in one line.

=head1 AUTHOR

Joern Reder <joern AT zyn.de>

=head1 COPYRIGHT

Copyright (C) 2004 by Joern Reder, All Rights Reserved.

This library is free software; you can redistribute it
and/or modify it under the same terms as Perl itself.

=head1 SEE ALSO

Mail::GPG, perl(1).

=cut






