package Mail::GPG::Test;

# $Id: Test.pm,v 1.2 2004/02/15 12:32:58 joern Exp $

use strict;

use Mail::GPG;
use MIME::Entity;
use MIME::Parser;
use Data::Dumper;
use File::Path;

use File::Temp qw(tempdir);

my $has_encode = eval { require Encode; 1 };

sub get_gpg_home_dir		{ shift->{gpg_home_dir}			}
sub set_gpg_home_dir		{ shift->{gpg_home_dir}		= $_[1]	}

#-- These methods return information about the shipped test key.
#-- The email adress has a German umlaut and colons
#-- to test the proper decoding of gpg --list-keys output.
sub get_key_id			{ 'E20F5035' }
sub get_key_sub_id		{ '196ED9E3' }
sub get_key_mail		{ 'J�rn Reder Mail::GPG Test Key <mailgpg@localdomain>' }
sub get_passphrase		{ 'test' }

sub new {
	my $class = shift;

	my $gpg_home_dir = tempdir (
		"mgpgXXXX", DIR => ".",
	);
	
	my $self = bless {
		gpg_home_dir	=> $gpg_home_dir
	}, $class;
	
	return $self;
}

sub DESTROY {
	my $self = shift;

	#-- tempdir ( CLEANUP => 1 ) seem not to work if
	#-- an exception occured, so we use this destructor
	#-- to remove the gpg home dir on exit.
	rmtree ( [ $self->get_gpg_home_dir ], 0, 0);

	1;
}

sub init {
	my $self = shift;

	my $gpg_home_dir = $self->get_gpg_home_dir;

	my $command =
		"gpg --batch --no-tty --homedir $gpg_home_dir".
		"    --import t/mgpg-test-key.pub.asc".
		"    >/dev/null 2>&1 && ".
		"gpg --batch --no-tty --homedir $gpg_home_dir".
		"    --allow-secret-key-import".
		"    --import t/mgpg-test-key.sec.asc".
		"    >/dev/null 2>&1 && echo MGPG_OK";

	my $output = qx[ $command ];

	return $output =~ /MGPG_OK/;
}

sub get_mail_gpg {
	my $self = shift;
	
	my $mg = Mail::GPG->new (
		debug		   => $ENV{DUMPFILES},
		default_key_id     => $self->get_key_id,
		default_passphrase => $self->get_passphrase,
		gnupg_hash_init    => {
			homedir      => $self->get_gpg_home_dir,
			always_trust => 1,
			
		},
	);
	
	return $mg;
}

sub get_test_mail_body {
	"This is a test mail body,\n".
	"with special characters: ����\n".
	"and lines with whitespace   \n".
	"and a cr/lf line ending\r\n".
	"and\n".
	"From at the beginning\n".
	"Let's see what happens.\n";
}

sub print_parse_entity {
	my $self = shift;
	my %par = @_;
	my  ($entity, $modify, $decode_bodies) =
	@par{'entity','modify','decode_bodies'};

	my ($fh, $file) = File::Temp::tempfile(
		'mgpgXXXXXXXX',
		DIR    => File::Spec->tmpdir,
		UNLINK => 1,
	);

	$entity->print($fh);
	close $fh;

	if ( $modify ) {
		open ($fh, $file) or die "can't read $file";
		my $data = join('',<$fh>);
		close $fh;
		$data =~ s/whitespace/spacewhite/g;
		$data =~ tr/L/l/;
		open ($fh, ">$file") or die "can't write $file";
		print $fh $data;
		close $fh;
	}

	open ($fh, $file) or die "can't read $file";
	my $parser = MIME::Parser->new;
	$parser->output_to_core(1);
	eval { $parser->decode_bodies($decode_bodies) };
	my $parsed_entity = $parser->parse($fh);
	close $fh;

	return $parsed_entity;
}

sub sign_test {
	my $self = shift;
	my %par = @_;
	my  ($mg, $method, $encoding, $attach, $invalid) =
	@par{'mg','method','encoding','attach','invalid'};

	$attach  = "" if not defined $attach;
	$invalid = "" if not defined $invalid;

	$attach  = " (w/ attachmnt)" if $attach;
	$invalid = "" if not $invalid;
	$invalid = " (invalid)"      if $invalid;

	my $test_name = "$method:$encoding Signature $attach$invalid";

	my $entity = MIME::Entity->build (
	    From     => $self->get_key_mail,
	    Subject  => "Mail::GPG Testmail",
	    Data     => [ $self->get_test_mail_body ],
	    Encoding => $encoding,
	    Charset  => "iso-8859-1",
	);

	if ( $attach ) {
		$entity->attach (
			Type        => "application/octet-stream",
			Disposition => "inline",
			Data        => [ "A great �tt�chment.  \n" x 10 ],
			Encoding    => "base64",
		);
	}

	my $signed_entity = $mg->$method (
	    entity => $entity
	);

	if ( not $mg->is_signed ( entity => $signed_entity ) ) {
		ok (0, "$test_name: Entity not signed");
		return;
	}

	my $parsed_entity = $self->print_parse_entity (
	    entity        => $signed_entity,
	    modify        => $invalid,
	    decode_bodies => ($method =~ /armor/)||0,
	);

	if ( $ENV{DUMPFILES} ) {
		my $tmp_file = "/tmp/$method-$encoding-".
				($attach?"attach":"noattach")."-".
				($invalid?"invalid":"valid");

		open(SEND,">$tmp_file.send");
		open(RETR,">$tmp_file.retr");

		print SEND $signed_entity->as_string;
		print RETR $parsed_entity->as_string;

		close SEND;
		close RETR;
	}

	my $result = eval {
		$mg->verify (
		  entity => $parsed_entity,
		);
	};

	my $error = $@;

	if ( not $invalid and $@ ) {
		ok (0, "$test_name: $@");
		return;
	}

	if ( not $invalid and (
	      $result->get_sign_key_id ne $self->get_key_id or
	      $result->get_sign_mail   ne $self->get_key_mail ) ) {
		ok (0, "Key/Email wrong");
		return;
	}

	if ( $invalid ) {
		if ( $error ) {
			ok (1, $test_name);
		} else {
			ok (!$result->get_sign_ok, $test_name);
		}
	} else {
#print $result->as_string;
		ok ($result->get_sign_ok, $test_name);
	}

	1;
}

sub enc_test {
	my $self = shift;
	my %par = @_;
	my  ($mg, $method, $encoding, $attach) =
	@par{'mg','method','encoding','attach'};

	$attach  = " (w/ attachmnt)" if $attach;
	$attach  = "" if not defined $attach;

	my $entity = MIME::Entity->build (
	    From     => $self->get_key_mail,
	    Subject  => "Mail::GPG Testmail",
	    Data     => [ $self->get_test_mail_body ],
	    Encoding => $encoding,
	    Charset  => "iso-8859-1",
	);

	if ( $attach ) {
		$entity->attach (
			Type        => "application/octet-stream",
			Disposition => "inline",
			Data        => [ "A great �tt�chment.  \n" x 10 ],
			Encoding    => "base64",
		);
	}

	my $enc_entity = $mg->$method (
	    entity     => $entity,
	    recipients => [ $self->get_key_mail ],
	);

	if ( not $mg->is_encrypted ( entity => $enc_entity ) ) {
		ok (0, "Entity not encrypted");
		return;
	}

	my $parsed_entity = $self->print_parse_entity (
	    entity        => $enc_entity,
	    decode_bodies => 1,
	);

	my ($dec_key_id, $dec_key_mail) = $mg->get_decrypt_key (
		entity => $parsed_entity,
	);

	if ( $has_encode ) {
		if ( $dec_key_id ne $self->get_key_id or
		     $dec_key_mail ne $self->get_key_mail ) {
		     	ok (0, "Decryption key or email wrong: ".
			       "$dec_key_id==".$self->get_key_id);
			return;
		}
	} else {
		if ( $dec_key_id ne $self->get_key_id ) {
		     	ok (0, "Decryption key or email wrong: ".
			       "$dec_key_id==".$self->get_key_id);
			return;
		}
	}

	my ($dec_entity, $result) = eval {
		$mg->decrypt (
		    entity => $parsed_entity,
		);
	};

	if ( $ENV{DUMPFILES} ) {
		my $tmp_file = "/tmp/$method-$encoding-".
				($attach?"attach":"noattach");

		open(SEND,">$tmp_file.send");
		open(RETR,">$tmp_file.retr");
	}

	if ( $method =~ /encrypt/ and $method !~ /sign/ and  (
	     $result->get_is_signed or
	     $result->get_sign_key_id or
	     $result->get_sign_mail  or
	     $result->get_sign_ok ) ) {
		ok (0, "Signature reported but message not signed");
		return;
	}

	if ( $method =~ /sign/ and (
	     not $result->get_sign_ok or
	     not $result->get_is_signed or
	     not $result->get_sign_key_id eq $self->get_key_id or
	     not $result->get_sign_mail   eq $self->get_key_mail ) ) {
		ok (0, "Signature bad");
		return;
	}

	if ( $has_encode ) {
		if ( not $result->get_is_encrypted or
		     not $result->get_enc_ok or
		     not $result->get_enc_key_id eq $self->get_key_sub_id or
		     not $result->get_enc_mail   eq $self->get_key_mail ) {
			ok (0, "Decryption failed");
			return;
		}
	} else {
		if ( not $result->get_is_encrypted or
		     not $result->get_enc_ok or
		     not $result->get_enc_key_id eq $self->get_key_sub_id ) {
			ok (0, "Decryption failed");
			return;
		}
	}
	if ( $method =~ /armor/ ) {
		my $entity_body = $entity->bodyhandle->as_string;
		ok ($dec_entity->bodyhandle->as_string eq $entity_body,
			"$method:$encoding Decryption$attach" );
		if ( $ENV{DUMPFILES} ) {
			print SEND $entity_body;
			print RETR $dec_entity->bodyhandle->as_string;
		}
	} elsif ( not $attach ) {
		ok ($dec_entity->body_as_string eq $entity->body_as_string,
			"$method:$encoding Decryption$attach" );
		if ( $ENV{DUMPFILES} ) {
			print SEND $entity->body_as_string;
			print RETR $dec_entity->body_as_string;
		}
	} else {
		ok (($dec_entity->parts(0)->body_as_string eq
		    $entity->parts(0)->body_as_string and
		    $dec_entity->parts(1)->body_as_string eq
		    $entity->parts(1)->body_as_string),
			"$method:$encoding Decryption$attach" );
		if ( $ENV{DUMPFILES} ) {
			print SEND $entity->body_as_string;
			print RETR $dec_entity->body_as_string;
		}
	}

	if ( $ENV{DUMPFILES} ) {
		close SEND;
		close RETR;
	}

	1;
}

sub big_test {
	my $self = shift;
	my %par = @_;
	my ($mg) = $par{'mg'};

	my @big_data = ( "This is a fat data body\n" x 200000 );

	my $entity = MIME::Entity->build (
	    From     => $self->get_key_mail,
	    Subject  => "Mail::GPG Testmail",
	    Data     => \@big_data,
	    Encoding => "base64",
	    Charset  => "iso-8859-1",
	);

	my $enc_entity = $mg->mime_sign_encrypt (
	    entity     => $entity,
	    recipients => [ $self->get_key_mail ],
	);

	if ( not $mg->is_encrypted ( entity => $enc_entity ) ) {
		ok (0, "Entity not encrypted");
		return;
	}

	my $parsed_entity = $self->print_parse_entity (
	    entity        => $enc_entity,
	    decode_bodies => 1,
	);

	my ($dec_key_id, $dec_key_mail) = $mg->get_decrypt_key (
		entity => $parsed_entity,
	);

	if ( $has_encode ) {
		if ( $dec_key_id ne $self->get_key_id or
		     $dec_key_mail ne $self->get_key_mail ) {
		     	ok (0, "Decryption key or email wrong: ".
			       "$dec_key_id==".$self->get_key_id);
			return;
		}
	} else {
		if ( $dec_key_id ne $self->get_key_id ) {
		     	ok (0, "Decryption key or email wrong: ".
			       "$dec_key_id==".$self->get_key_id);
			return;
		}
	}

	my ($dec_entity, $result) = eval {
		$mg->decrypt (
		    entity => $parsed_entity,
		);
	};

	if ( not $result->get_sign_ok or
	     not $result->get_is_signed or
	     not $result->get_sign_key_id eq $self->get_key_id or
	     not $result->get_sign_mail   eq $self->get_key_mail ) {
		ok (0, "Signature bad");
		return;
	}

	if ( $has_encode ) {
		if ( not $result->get_is_encrypted or
		     not $result->get_enc_ok or
		     not $result->get_enc_key_id eq $self->get_key_sub_id or
		     not $result->get_enc_mail   eq $self->get_key_mail ) {
			ok (0, "Decryption failed");
			return;
		}
	} else {
		if ( not $result->get_is_encrypted or
		     not $result->get_enc_ok or
		     not $result->get_enc_key_id eq $self->get_key_sub_id ) {
			ok (0, "Decryption failed");
			return;
		}
	}

	ok (1, "Big entity");
	
	1;
}

1;