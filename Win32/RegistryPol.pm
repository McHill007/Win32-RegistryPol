package Win32::RegistryPol;
require Exporter;


@ISA    = qw( Exporter );
@EXPORT = qw( REG_NONE REG_SZ REG_EXPAND_SZ REG_BINARY REG_DWORD REG_MULTI_SZ REG_QWORD );  

# +----------------------------------------------------------------------+
# |                         USED PERL MODULES                            |
# +----------------------------------------------------------------------+
use strict ;
use warnings;
use Carp qw();
use Data::Dumper;
use Encode qw(decode encode);
use File::Slurp;
no autovivification; 

# +----------------------------------------------------------------------+
# |                        PREDEFINED VALUES                             
# +----------------------------------------------------------------------+
use constant DIRECTORY_SEPARATOR => "\\";

# Registry data types
use constant REG_NONE           => 0;
use constant REG_SZ             => 1;
use constant REG_EXPAND_SZ      => 2;
use constant REG_BINARY         => 3;
use constant REG_DWORD          => 4;
use constant REG_MULTI_SZ       => 7;
use constant REG_QWORD			=> 11;


use constant REG_DWORD_BIG_ENDIAN => 5;
use constant REG_DWORD_LITTLE_ENDIAN => 4;
use constant REG_QWORD_LITTLE_ENDIAN => 11;

my %RegTypes =( 
0 	=> "REG_NONE",
1	=> "REG_SZ",
2 	=> "REG_EXPAND_SZ",
3 	=> "REG_BINARY",
4 	=> "REG_DWORD",
7 	=> "REG_MULTI_SZ",
11	=> "REG_QWORD");




# +----------------------------------------------------------------------+
# | Function: new
# +----------------------------------------------------------------------+
# | Description: Class constructor
# +----------------------------------------------------------------------+
sub new 
{
	my $class = shift;
	my $self->{'options'} = shift ;

	Carp::croak("Win32::RegistryPol::new - invalid or missing options.") if ( !$self->{'options'}->{'inputfile'} && $self->{'options'}->{'scope'} )  ;
	Carp::croak("Win32::RegistryPol::new - invalid scope option.") if ( $self->{'options'}->{'scope'} && $self->{'options'}->{'scope'} !~ m/(user|machine)/i ) ;
	bless $self, $class;
	return $self;
}


# +----------------------------------------------------------------------+
# | Function: load
# +----------------------------------------------------------------------+
# | Description: Load registry pol file
# +----------------------------------------------------------------------+ 
sub load 
{
	my $self = shift;
	

	
	if ( defined($self->{'options'}->{'scope'}) )
	{
		my @files = ( $ENV{'windir'} . DIRECTORY_SEPARATOR .  "Sysnative" . DIRECTORY_SEPARATOR . "GroupPolicy" . DIRECTORY_SEPARATOR . $self->{'options'}->{'scope'} . DIRECTORY_SEPARATOR . "Registry.pol",
					  $ENV{'windir'} . DIRECTORY_SEPARATOR .  "System32" . DIRECTORY_SEPARATOR . "GroupPolicy" . DIRECTORY_SEPARATOR . $self->{'options'}->{'scope'} . DIRECTORY_SEPARATOR . "Registry.pol"
					) ;
		foreach ( @files ) 
		{
			$self->{'options'}->{'inputfile'} = $_ if ( -f $_ ) ; ;
		}
	}
	$self->__loadfile() if ( -f $self->{'options'}->{'inputfile'} ) ;
	$self->__initfile() if ( !-f $self->{'options'}->{'inputfile'} ) ;
	return ( $self->{'poldata'} ) ;
}

# +----------------------------------------------------------------------+
# | Function: getData
# +----------------------------------------------------------------------+
# | Description:Get key data
# +----------------------------------------------------------------------+ 
sub getData
{
	my $self = shift ;
	my ( $key, $name ) = @_ ;
	my ($p) = grep { $_->{$name} } @{$self->{'poldata'}->{$key}};
	return unless ( defined($p->{$name}) ) ;
	return ( (split(/[A-Z_]+\:(.*)/, $p->{$name}))[1] ) ;
}


# +----------------------------------------------------------------------+
# | Function: getType
# +----------------------------------------------------------------------+
# | Description:Get data type
# +----------------------------------------------------------------------+ 
sub getType
{
	my $self = shift ;
	my ( $key, $name ) = @_ ;
	my ($p) = grep { $_->{$name} } @{$self->{'poldata'}->{$key}};
	return  unless ( defined($p->{$name}) ) ;
	return ( (split(/([A-Z_]+)\:(.*)/, $p->{$name}))[1] ) ;
}

# +----------------------------------------------------------------------+
# | Function: setKey
# +----------------------------------------------------------------------+
# | Description:Set new key
# +----------------------------------------------------------------------+ 
sub setKey
{
	my $self = shift ;
	my ( $key, $name, $value, $type ) = @_ ;
	Carp::croak("Win32::RegistryPol::setKey - Key information missing.") if ( !$key ) ;
	Carp::croak("Win32::RegistryPol::setKey - Unknown Type.") if ( defined($type) && $type !~ m/(0|1|2|4|5|11)/ ) ;
	
	

	my ( $dKey, $dName, $dValue ) = ( $key, $name, $value ) ;

	$name = '' unless ( $name )  ;
	$dKey = __addTerminalNull(__utf162hexle($key)) ;
	$dName = $name ? __addTerminalNull(__utf162hexle($name)) : __addTerminalNull(__utf162hexle('')) ;
	$type = $type ? $type : 0 ;
	$value = $value ? $value : '' ;
	
	
	
	if($type == 1 || $type == 2) { # REG_SZ || REG_EXPAND_SZ
		$dValue = __addTerminalNull(__utf162hexle($value));
	}
	elsif($type == 4) { # REG_DWORD
		$dValue = __int322hexle($value);
	}
	elsif($type == 5) { # REG_DWORD_BIG_ENDIAN
		$dValue = __int322hexbe($value);
	}
	elsif($type == 0){
		$dValue = __addTerminalNull(__utf162hexle(''));
	}	
	elsif($type){
		Carp::croak("Win32::RegistryPol::setKey - Unkown type.") if ( !$key ) ;	
	}
	my $dSize = __int322hexle((length($dValue)/2)) ;


	# if($type == 7) { # REG_MULTI_SZ / not available
	# }

	if($type == 11) { # REG_QWORD
		$dValue = __int642hexle($value);
	}	
	
	my $newKey = "5b00" . $dKey . "3b00" . $dName . "3b00" . __int322hexle($type) . "3b00" . $dSize . "3b00" . $dValue ;
	
	
	my %finaldata = ( $name => $RegTypes{$type} . ":" . $value ,
					'size' => length($dValue)/2,
					"body" => $newKey					) ;
	
	push @{$self->{'poldata'}->{$key}}, \%finaldata ;
}



# +----------------------------------------------------------------------+
# | Function: deleteKey
# +----------------------------------------------------------------------+
# | Description:Delete key from store
# +----------------------------------------------------------------------+ 
sub deleteKey
{
	my $self = shift ;
	my ( $key, $name ) = @_ ;
	
	Carp::croak("Win32::RegistryPol::setKey - Key information missing.") if ( !$key ) ;
	undef($self->{'poldata'}->{$key}) if ( defined ( $self->{'poldata'}->{$key} ) && !$name ) ;
	@{$self->{'poldata'}->{$key}} = grep { !$_->{$name} } @{$self->{'poldata'}->{$key}} if ( $name ) ;
}

# +----------------------------------------------------------------------+
# | Function: store
# +----------------------------------------------------------------------+
# | Description:Store data to file
# +----------------------------------------------------------------------+ 
sub store
{
	my $self = shift ;
	my $outpufile = shift ;
	
	$self->{'options'}->{'outpufile'} = $self->{'options'}->{'inputfile'} if ( !$outpufile && !defined($self->{'options'}->{'outpufile'}) ) ;
	$self->{'options'}->{'outpufile'} = $outpufile if ( defined($outpufile) ) ;
	
	my @body = () ;
	foreach my $key ( keys %{$self->{'poldata'}} )
	{
		foreach my $data ( @{$self->{'poldata'}->{$key}} )
		{
			push @body, $data->{'body'} ;
		}
	}
	
	my $body = join('5d00',@body) . "5d00" ;
	my $raw_data = pack('H8 H8 H*', $self->{'__init'}->{'sig'},$self->{'__init'}->{'ver'},$body);
	write_file($self->{'options'}->{'outpufile'},  $raw_data) or die ("Unable to write policy file");
	
}



# +----------------------------------------------------------------------+
# | Function: __initfile
# +----------------------------------------------------------------------+
# | Description: init new pol file
# +----------------------------------------------------------------------+ 
sub __initfile
{
	my $self = shift ;
	$self->{'__init'}->{'sig'} = "50526567" ;	
	$self->{'__init'}->{'ver'} = "01000000" ;
}



# +----------------------------------------------------------------------+
# | Function: __loadfile
# +----------------------------------------------------------------------+
# | Description: load existing pol file
# +----------------------------------------------------------------------+ 
sub __loadfile
{
	my $self = shift;	
	
	my $_data = read_file($self->{'options'}->{'inputfile'});
	

	
	my ($sig, $ver, $body)  = unpack('H8 H8 H*', $_data);
	
	
	$sig == "50526567" or die "bad header (signature $sig)";
	$ver == "01000000" or die "bad header (version $ver)";	


	$self->{'__init'}->{'sig'} = $sig ;	
	$self->{'__init'}->{'ver'} = $ver ;
	
	
	my @body = split /5d00/, $body;
	
		
	foreach my $bodyItem ( @body )
	{
		$bodyItem =~ m/5b00(?<key>.*?)3b00(?<value>.*?)3b00(?<type>.*?)3b00(?<size>.*?)3b00(?<data>.*)/i ; 

		my $key  	= __hex2utf16le(__stripTerminalNull($+{'key'})) ;
		my $value 	= __hex2utf16le(__stripTerminalNull($+{'value'})) ;
		my $type 	= __hex2int32le($+{'type'}) ;
		my $size	= __hex2int32le($+{'size'}) ;
		my $data	= $+{'data'} ;
		my %finaldata ;
		
		next unless ( $key ) ;
		
		if($type == 1 || $type == 2) { # REG_SZ || REG_EXPAND_SZ
			$data = __hex2utf16le($data);
		}

		if($type == 3) { # REG_BINARY
		}

		if($type == 4) { # REG_DWORD
			$data = __hex2int32le($data);
		}

		if($type == 5) { # REG_DWORD_BIG_ENDIAN
			$data = __hex2int32be($data);
		}

		if($type == 7) { # REG_MULTI_SZ / not available
		}

		if($type == 11) { # REG_QWORD
			$data = __hex2int64le($data);
		}

		%finaldata = ( $value => $RegTypes{$type} . ":" . $data ,
						'size' => $size,
						'body' => $bodyItem		) ;
		
		push @{$self->{'poldata'}->{$key}}, \%finaldata ;
		
	}

}





# strip a terminal UTF-16 null (0000)
sub __stripTerminalNull {
  my $a=shift;
  $a =~ s/(.*)0000/$1/ ;
  return $a;
}
sub __addTerminalNull {
  return shift . "0000";
}





# convert hex string to utf-16le
sub __hex2utf16le {
  return decode("UTF-16LE", pack('H*', shift));
}
sub __utf162hexle {
  return unpack('H*',encode("UTF-16LE",  shift));
}



sub __hex2int32le {
  return unpack('L<', pack('H*', shift));
}
sub __int322hexle {
  return unpack('H*',pack('L<',  shift));
}



sub __hex2int32be {
  return unpack('L>', pack('H*', shift));
}
sub __int322hexbe {
  return unpack('H*', pack('L>', shift));
}


sub __hex2int64le {
  return unpack('Q>', pack('H*', shift));
}
sub __int642hexle {
  return unpack('H*', pack('Q>', shift));
}


1;