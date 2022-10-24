# Win32-RegistryPol
 Modify local policy file (Registry.pol)


```perl
use Data::Dumper;
no autovivification;


#If no outputfile defined, inputfile will be overwritten
use Win32::RegistryPol ;
$object = new Win32::RegistryPol({'inputfile' => 'registry.pol', 'outpufile' => 'testoutput.pol'});

#Load or create file - returns hash ref with all data
my $data = $object->load();
#print Dumper($data ) ;


#Get existing value - empty if not exists
my $value = $object->getData('Software\Policies\Microsoft\Windows\EventLog\System','MaxSize') ;
print $value . "\n" ;



#A semicolon-delimited list of values to delete.
$object->setKey("SOFTWARE\\Test\\delvalue",'**DeleteValues',"value1;value2;value3",REG_SZ) ;
#Deletes a single value
$object->setKey("SOFTWARE\\Test\\delvalue",'**Del.gone3','',REG_SZ) ;
#Deletes all values in a key
$object->setKey("SOFTWARE\\Test\\delvalues",'**DelVals','',REG_SZ) ;
#A semicolon-delimited list of keys to delete
$object->setKey("SOFTWARE\\Test\\delkeys",'**DeleteKeys',"key1;key2;key3",REG_SZ) ;
#secures the key, giving administrators and the system full control, and giving users read-only access
$object->setKey("SOFTWARE\\Test\\secure",'**SecureKey',"1",REG_DWORD) ;

#Set values
$object->setKey("SOFTWARE\\test\\values",'dwordvalue', 800, REG_DWORD) ;
$object->setKey("SOFTWARE\\test\\values",'stringvalue', "Teststring", REG_SZ) ;
$object->setKey('SOFTWARE\\test\\keyonly') ;

#delete full keys or names
$object->deleteKey('Software\\Policies\\Microsoft\\EMET\\Defaults','Wordpad') ;
$object->deleteKey('Software\\Policies\\Microsoft\\EMET\\Defaults') ;



$object->store();


```
