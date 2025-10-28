#-*- mode: cperl; eval: (follow-mode) -*-

package Umi::Constants;

use utf8;
use strict;
use warnings;
use Exporter 'import';

our @EXPORT_OK = qw(
		     COUNTRIES
		     DNS
		     GENDER
		     RE
		     SARGON
		     TRANSLIT
		     UMIAUTH
		     UMIOVPNADDDEVOS
		     UMIOVPNADDDEVTYPE
		     UMIOVPNADDSTATUS
		  );

use constant {
	      RE => {
		     ip    => '(?:(?:[0-9]|[1-9]\d|1\d{2}|2[0-4]\d|25[0-5])\.){3}(?:[0-9]|[1-9]\d|1\d{2}|2[0-4]\d|25[0-5])',
		     net3b => '(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){2}',
		     net2b => '(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){1}',
		     mac => {
			     # 00:1A:2B:3C:4D:5E or 00-1A-2B-3C-4D-5E (MAC-48 IEEE canonical, EUI-48)
			     mac48 => '(?:[[:xdigit:]]{2}([-:]))(?:[[:xdigit:]]{2}\1){4}[[:xdigit:]]{2}',
			     # 001a.2b3c.4d5e (https://stackoverflow.com/a/21457070)
			     cisco => '(?:[[:xdigit:]]{4})(?:([\.])[[:xdigit:]]{4}){2}',
			     # 001A2B3C4D5E
			     plain => '[[:xdigit:]]{12}',
			    },
		    },
	      UMIAUTH => {
			  # roles weights (supposed to be used in is_authorized method)
			  role => {
				   admin => 0,
				   coadmin => 1,
				   hr => 2,
				   operator => 3,
				  },
			 },
	      UMIOVPNADDSTATUS => {
				disabled => 0,
				enabled => 1
			       },
	      UMIOVPNADDDEVTYPE => [qw( notebook macbook wrt desktop phone other )],
	      UMIOVPNADDDEVOS => [qw( windows unix macos ios android other )],
	      # ISO 5218 Representation of human sex
	      GENDER => {
			 0 => 'Not known',
			 1 => 'Male',
			 2 => 'Female',
			 9 => 'Not applicable',
			},
	      DNS => {
		       NOERROR           => { dec =>  0, RFC => 1035, descr => 'No Error', },
		       FORMERR           => { dec =>  1, RFC => 1035, descr => 'Format Error', },
		       SERVFAIL          => { dec =>  2, RFC => 1035, descr => 'Server Failure', },
		       NXDOMAIN          => { dec =>  3, RFC => 1035, descr => 'Non-Existent Domain', },
		       NOTIMP            => { dec =>  4, RFC => 1035, descr => 'Not Implemented', },
		       REFUSED           => { dec =>  5, RFC => 1035, descr => 'Query Refused', },
		       YXDOMAIN          => { dec =>  6, RFC => 2136, descr => 'Name Exists when it should not',},
		       YXRRSET           => { dec =>  7, RFC => 2136, descr => 'RR Set Exists when it should not',},
		       NXRRSET           => { dec =>  8, RFC => 2136, descr => 'RR Set that should exist does not', },
		       NOTAUTH           => { dec =>  9, RFC => 2136, descr => 'Server Not Authoritative for zone', },
		       NOTZONE           => { dec => 10, RFC => 2136, descr => 'Name not contained in zone', },
		       BADVERS           => { dec => 16, RFC => 2671, descr => 'Bad OPT Version', },
		       BADSIG            => { dec => 16, RFC => 2845, descr => 'TSIG Signature Failure', },
		       BADKEY            => { dec => 17, RFC => 2845, descr => 'Key not recognized', },
		       BADTIME           => { dec => 18, RFC => 2845, descr => 'Signature out of time window', },
		       BADMODE           => { dec => 19, RFC => 2930, descr => 'Bad TKEY Mode', },
		       BADNAME           => { dec => 20, RFC => 2930, descr => 'Duplicate key name', },
		       BADALG            => { dec => 21, RFC => 2930, descr => 'Algorithm not supported', },
		       'query timed out' => { dec => '', RFC => '',   descr => 'query timed out'},
		     },
	      SARGON => {
			 ENDPOINTS => {
				       'ALL'                      => 'ALL',
				       'BuildPrune'		  => 'BuildPrune --- Delete builder cache.',
				       'ConfigCreate'		  => 'ConfigCreate --- Create a config.',
				       'ConfigDelete'		  => 'ConfigDelete --- Delete a config.',
				       'ConfigInspect'		  => 'ConfigInspect --- Inspect a config.',
				       'ConfigList'		  => 'ConfigList --- List configs.',
				       'ConfigUpdate'		  => 'ConfigUpdate --- Update a config.',
				       'ContainerArchive'	  => 'ContainerArchive --- Get an archive of a filesystem resource in a container.',
				       'ContainerArchiveInfo'	  => 'ContainerArchiveInfo --- Get information about files in a container.',
				       'ContainerAttach'	  => 'ContainerAttach --- Attach to a container.',
				       'ContainerAttachWebsocket' => 'ContainerAttachWebsocket --- Attach to a container via a websocket.',
				       'ContainerChanges'	  => 'ContainerChanges --- Get changes on a container’s filesystem.',
				       'ContainerCreate'	  => 'ContainerCreate --- Create a container.',
				       'ContainerDelete'	  => 'ContainerDelete --- Remove a container.',
				       'ContainerExec'		  => 'ContainerExec --- Create an exec instance.',
				       'ContainerExport'	  => 'ContainerExport --- Export a container.',
				       'ContainerInspect'	  => 'ContainerInspect --- Inspect a container.',
				       'ContainerKill'		  => 'ContainerKill --- Kill a container.',
				       'ContainerList'		  => 'ContainerList --- List containers.',
				       'ContainerLogs'		  => 'ContainerLogs --- Get container logs.',
				       'ContainerPause'		  => 'ContainerPause --- Pause a container.',
				       'ContainerPrune'		  => 'ContainerPrune --- Delete stopped containers.',
				       'ContainerRename'	  => 'ContainerRename --- Rename a container.',
				       'ContainerResize'	  => 'ContainerResize --- Resize a container TTY.',
				       'ContainerRestart'	  => 'ContainerRestart --- Restart a container.',
				       'ContainerStart'		  => 'ContainerStart --- Start a container.',
				       'ContainerStats'		  => 'ContainerStats --- Get container stats based on resource usage.',
				       'ContainerStop'		  => 'ContainerStop --- Stop a container.',
				       'ContainerTop'		  => 'ContainerTop --- List processes running inside a container.',
				       'ContainerUnpause'	  => 'ContainerUnpause --- Unpause a container.',
				       'ContainerUpdate'	  => 'ContainerUpdate --- Update a container.',
				       'ContainerWait'		  => 'ContainerWait --- Wait for a container.',
				       'DistributionInspect'	  => 'DistributionInspect --- Get image information from the registry.',
				       'ExecInspect'		  => 'ExecInspect --- Inspect an exec instance.',
				       'ExecResize'		  => 'ExecResize --- Resize an exec instance.',
				       'ExecStart'		  => 'ExecStart --- Start an exec instance.',
				       'GetPluginPrivileges'	  => 'GetPluginPrivileges --- Get plugin privileges.',
				       'ImageBuild'		  => 'ImageBuild --- Build an image.',
				       'ImageCommit'		  => 'ImageCommit --- Create a new image from a container.',
				       'ImageCreate'		  => 'ImageCreate --- Create an image.',
				       'ImageDelete'		  => 'ImageDelete --- Remove an image.',
				       'ImageGet'		  => 'ImageGet --- Export an image.',
				       'ImageGetAll'		  => 'ImageGetAll --- Export several images.',
				       'ImageHistory'		  => 'ImageHistory --- Get the history of an image.',
				       'ImageInspect'		  => 'ImageInspect --- Inspect an image.',
				       'ImageList'		  => 'ImageList --- List Images.',
				       'ImageLoad'		  => 'ImageLoad --- Import images.',
				       'ImagePrune'		  => 'ImagePrune --- Delete unused images.',
				       'ImagePush'		  => 'ImagePush --- Push an image.',
				       'ImageSearch'		  => 'ImageSearch --- Search images.',
				       'ImageTag'		  => 'ImageTag --- Tag an image.',
				       'NetworkConnect'		  => 'NetworkConnect --- Connect a container to a network.',
				       'NetworkCreate'		  => 'NetworkCreate --- Create a network.',
				       'NetworkDelete'		  => 'NetworkDelete --- Remove a network.',
				       'NetworkDisconnect'	  => 'NetworkDisconnect --- Disconnect a container from a network.',
				       'NetworkInspect'		  => 'NetworkInspect --- Inspect a network.',
				       'NetworkList'		  => 'NetworkList --- List networks.',
				       'NetworkPrune'		  => 'NetworkPrune --- Delete unused networks.',
				       'NodeDelete'		  => 'NodeDelete --- Delete a node.',
				       'NodeInspect'		  => 'NodeInspect --- Inspect a node.',
				       'NodeList'		  => 'NodeList --- List nodes.',
				       'NodeUpdate'		  => 'NodeUpdate --- Update a node.',
				       'PluginCreate'		  => 'PluginCreate --- Create a plugin.',
				       'PluginDelete'		  => 'PluginDelete --- Remove a plugin.',
				       'PluginDisable'		  => 'PluginDisable --- Disable a plugin.',
				       'PluginEnable'		  => 'PluginEnable --- Enable a plugin.',
				       'PluginInspect'		  => 'PluginInspect --- Inspect a plugin.',
				       'PluginList'		  => 'PluginList --- List plugins.',
				       'PluginPull'		  => 'PluginPull --- Install a plugin.',
				       'PluginPush'		  => 'PluginPush --- Push a plugin.',
				       'PluginSet'		  => 'PluginSet --- Configure a plugin.',
				       'PluginUpgrade'		  => 'PluginUpgrade --- Upgrade a plugin.',
				       'PutContainerArchive'	  => 'PutContainerArchive --- Extract an archive of files or folders to a directory in a container.',
				       'SecretCreate'		  => 'SecretCreate --- Create a secret.',
				       'SecretDelete'		  => 'SecretDelete --- Delete a secret.',
				       'SecretInspect'		  => 'SecretInspect --- Inspect a secret.',
				       'SecretList'		  => 'SecretList --- List secrets.',
				       'SecretUpdate'		  => 'SecretUpdate --- Update a Secret.',
				       'ServiceCreate'		  => 'ServiceCreate --- Create a service.',
				       'ServiceDelete'		  => 'ServiceDelete --- Delete a service.',
				       'ServiceInspect'		  => 'ServiceInspect --- Inspect a service.',
				       'ServiceList'		  => 'ServiceList --- List services.',
				       'ServiceLogs'		  => 'ServiceLogs --- Get service logs.',
				       'ServiceUpdate'		  => 'ServiceUpdate --- Update a service.',
				       'Session'		  => 'Session --- Initialize interactive session.',
				       'SwarmInit'		  => 'SwarmInit --- Initialize a new swarm.',
				       'SwarmInspect'		  => 'SwarmInspect --- Inspect swarm.',
				       'SwarmJoin'		  => 'SwarmJoin --- Join an existing swarm.',
				       'SwarmLeave'		  => 'SwarmLeave --- Leave a swarm.',
				       'SwarmUnlock'		  => 'SwarmUnlock --- Unlock a locked manager.',
				       'SwarmUnlockkey'		  => 'SwarmUnlockkey --- Get the unlock key.',
				       'SwarmUpdate'		  => 'SwarmUpdate --- Update a swarm.',
				       'SystemAuth'		  => 'SystemAuth --- Check auth configuration.',
				       'SystemDataUsage'	  => 'SystemDataUsage --- Get data usage information.',
				       'SystemEvents'		  => 'SystemEvents --- Monitor events.',
				       'SystemInfo'		  => 'SystemInfo --- Get system information.',
				       'SystemPing'		  => 'SystemPing --- Ping.',
				       'SystemVersion'		  => 'SystemVersion --- Get version.',
				       'TaskInspect'		  => 'TaskInspect --- Inspect a task.',
				       'TaskList'		  => 'TaskList --- List tasks.',
				       'TaskLogs'		  => 'TaskLogs --- Get task logs.',
				       'VolumeCreate'		  => 'VolumeCreate --- Create a volume.',
				       'VolumeDelete'		  => 'VolumeDelete --- Remove a volume.',
				       'VolumeInspect'		  => 'VolumeInspect --- Inspect a volume.',
				       'VolumeList'		  => 'VolumeList --- List volumes.',
				       'VolumePrune'		  => 'VolumePrune --- Delete unused volumes.',
				      },
			 CAPABILITIES => [qw(
					      CAP_AUDIT_READ
					      CAP_AUDIT_WRITE
					      CAP_BLOCK_SUSPEND
					      CAP_CHOWN
					      CAP_DAC_OVERRIDE
					      CAP_DAC_READ_SEARCH
					      CAP_FOWNER
					      CAP_FSETID
					      CAP_IPC_LOCK
					      CAP_IPC_OWNER
					      CAP_KILL
					      CAP_LEASE
					      CAP_LINUX_IMMUTABLE
					      CAP_MAC_ADMIN
					      CAP_MAC_OVERRIDE
					      CAP_MKNOD
					      CAP_NET_ADMIN
					      CAP_NET_BIND_SERVICE
					      CAP_NET_BROADCAST
					      CAP_NET_RAW
					      CAP_SETFCAP
					      CAP_SETGID
					      CAP_SETPCAP
					      CAP_SETUID
					      CAP_SYSLOG
					      CAP_SYS_ADMIN
					      CAP_SYS_BOOT
					      CAP_SYS_CHROOT
					      CAP_SYS_MODULE
					      CAP_SYS_NICE
					      CAP_SYS_PACCT
					      CAP_SYS_PTRACE
					      CAP_SYS_RAWIO
					      CAP_SYS_RESOURCE
					      CAP_SYS_TIME
					      CAP_SYS_TTY_CONFIG
					      CAP_WAKE_ALARM
					      CAP_AUDIT_CONTROL
					   )],
			},
	      # ISO 3166 country codes
	      COUNTRIES => {
			    'Afghanistan'					   => { two => 'AF', three =>'AFG', num => '004' },
			    'Albania'						   => { two => 'AL', three =>'ALB', num => '008' },
			    'Åland Islands'					   => { two => 'AX', three =>'ALA', num => '248' },
			    'Algeria'						   => { two => 'DZ', three =>'DZA', num => '012' },
			    'American Samoa'					   => { two => 'AS', three =>'ASM', num => '016' },
			    'Andorra'						   => { two => 'AD', three =>'AND', num => '020' },
			    'Angola'						   => { two => 'AO', three =>'AGO', num => '024' },
			    'Anguilla'						   => { two => 'AI', three =>'AIA', num => '660' },
			    'Antarctica'					   => { two => 'AQ', three =>'ATA', num => '010' },
			    'Antigua and Barbuda'				   => { two => 'AG', three =>'ATG', num => '028' },
			    'Argentina'						   => { two => 'AR', three =>'ARG', num => '032' },
			    'Armenia'						   => { two => 'AM', three =>'ARM', num => '051' },
			    'Aruba'						   => { two => 'AW', three =>'ABW', num => '533' },
			    'Australia'						   => { two => 'AU', three =>'AUS', num => '036' },
			    'Austria'						   => { two => 'AT', three =>'AUT', num => '040' },
			    'Azerbaijan'					   => { two => 'AZ', three =>'AZE', num => '031' },
			    'Bahamas'						   => { two => 'BS', three =>'BHS', num => '044' },
			    'Bahrain'						   => { two => 'BH', three =>'BHR', num => '048' },
			    'Bangladesh'					   => { two => 'BD', three =>'BGD', num => '050' },
			    'Barbados'						   => { two => 'BB', three =>'BRB', num => '052' },
			    'Belarus'						   => { two => 'BY', three =>'BLR', num => '112' },
			    'Belgium'						   => { two => 'BE', three =>'BEL', num => '056' },
			    'Belize'						   => { two => 'BZ', three =>'BLZ', num => '084' },
			    'Benin'						   => { two => 'BJ', three =>'BEN', num => '204' },
			    'Bermuda'						   => { two => 'BM', three =>'BMU', num => '060' },
			    'Bhutan'						   => { two => 'BT', three =>'BTN', num => '064' },
			    'Bolivia, Plurinational State of'			   => { two => 'BO', three =>'BOL', num => '068' },
			    'Bonaire, Sint Eustatius and Saba'			   => { two => 'BQ', three =>'BES', num => '535' },
			    'Bosnia and Herzegovina'				   => { two => 'BA', three =>'BIH', num => '070' },
			    'Botswana'						   => { two => 'BW', three =>'BWA', num => '072' },
			    'Bouvet Island'					   => { two => 'BV', three =>'BVT', num => '074' },
			    'Brazil'						   => { two => 'BR', three =>'BRA', num => '076' },
			    'British Indian Ocean Territory'			   => { two => 'IO', three =>'IOT', num => '086' },
			    'Brunei Darussalam'					   => { two => 'BN', three =>'BRN', num => '096' },
			    'Bulgaria'						   => { two => 'BG', three =>'BGR', num => '100' },
			    'Burkina Faso'					   => { two => 'BF', three =>'BFA', num => '854' },
			    'Burundi'						   => { two => 'BI', three =>'BDI', num => '108' },
			    'Cambodia'						   => { two => 'KH', three =>'KHM', num => '116' },
			    'Cameroon'						   => { two => 'CM', three =>'CMR', num => '120' },
			    'Canada'						   => { two => 'CA', three =>'CAN', num => '124' },
			    'Cabo Verde'					   => { two => 'CV', three =>'CPV', num => '132' },
			    'Cayman Islands'					   => { two => 'KY', three =>'CYM', num => '136' },
			    'Central African Republic'				   => { two => 'CF', three =>'CAF', num => '140' },
			    'Chad'						   => { two => 'TD', three =>'TCD', num => '148' },
			    'Chile'						   => { two => 'CL', three =>'CHL', num => '152' },
			    'China'						   => { two => 'CN', three =>'CHN', num => '156' },
			    'Christmas Island'					   => { two => 'CX', three =>'CXR', num => '162' },
			    'Cocos (Keeling) Islands'				   => { two => 'CC', three =>'CCK', num => '166' },
			    'Colombia'						   => { two => 'CO', three =>'COL', num => '170' },
			    'Comoros'						   => { two => 'KM', three =>'COM', num => '174' },
			    'Congo'						   => { two => 'CG', three =>'COG', num => '178' },
			    'Congo, Democratic Republic of the'			   => { two => 'CD', three =>'COD', num => '180' },
			    'Cook Islands'					   => { two => 'CK', three =>'COK', num => '184' },
			    'Costa Rica'					   => { two => 'CR', three =>'CRI', num => '188' },
			    'Côte d\'Ivoire'					   => { two => 'CI', three =>'CIV', num => '384' },
			    'Croatia'						   => { two => 'HR', three =>'HRV', num => '191' },
			    'Cuba'						   => { two => 'CU', three =>'CUB', num => '192' },
			    'Curaçao'						   => { two => 'CW', three =>'CUW', num => '531' },
			    'Cyprus'						   => { two => 'CY', three =>'CYP', num => '196' },
			    'Czech Republic'					   => { two => 'CZ', three =>'CZE', num => '203' },
			    'Denmark'						   => { two => 'DK', three =>'DNK', num => '208' },
			    'Djibouti'						   => { two => 'DJ', three =>'DJI', num => '262' },
			    'Dominica'						   => { two => 'DM', three =>'DMA', num => '212' },
			    'Dominican Republic'				   => { two => 'DO', three =>'DOM', num => '214' },
			    'Ecuador'						   => { two => 'EC', three =>'ECU', num => '218' },
			    'Egypt'						   => { two => 'EG', three =>'EGY', num => '818' },
			    'El Salvador'					   => { two => 'SV', three =>'SLV', num => '222' },
			    'Equatorial Guinea'					   => { two => 'GQ', three =>'GNQ', num => '226' },
			    'Eritrea'						   => { two => 'ER', three =>'ERI', num => '232' },
			    'Estonia'						   => { two => 'EE', three =>'EST', num => '233' },
			    'Ethiopia'						   => { two => 'ET', three =>'ETH', num => '231' },
			    'Falkland Islands (Malvinas)'			   => { two => 'FK', three =>'FLK', num => '238' },
			    'Faroe Islands'					   => { two => 'FO', three =>'FRO', num => '234' },
			    'Fiji'						   => { two => 'FJ', three =>'FJI', num => '242' },
			    'Finland'						   => { two => 'FI', three =>'FIN', num => '246' },
			    'France'						   => { two => 'FR', three =>'FRA', num => '250' },
			    'French Guiana'					   => { two => 'GF', three =>'GUF', num => '254' },
			    'French Polynesia'					   => { two => 'PF', three =>'PYF', num => '258' },
			    'French Southern Territories'			   => { two => 'TF', three =>'ATF', num => '260' },
			    'Gabon'						   => { two => 'GA', three =>'GAB', num => '266' },
			    'Gambia'						   => { two => 'GM', three =>'GMB', num => '270' },
			    'Georgia'						   => { two => 'GE', three =>'GEO', num => '268' },
			    'Germany'						   => { two => 'DE', three =>'DEU', num => '276' },
			    'Ghana'						   => { two => 'GH', three =>'GHA', num => '288' },
			    'Gibraltar'						   => { two => 'GI', three =>'GIB', num => '292' },
			    'Greece'						   => { two => 'GR', three =>'GRC', num => '300' },
			    'Greenland'						   => { two => 'GL', three =>'GRL', num => '304' },
			    'Grenada'						   => { two => 'GD', three =>'GRD', num => '308' },
			    'Guadeloupe'					   => { two => 'GP', three =>'GLP', num => '312' },
			    'Guam'						   => { two => 'GU', three =>'GUM', num => '316' },
			    'Guatemala'						   => { two => 'GT', three =>'GTM', num => '320' },
			    'Guernsey'						   => { two => 'GG', three =>'GGY', num => '831' },
			    'Guinea'						   => { two => 'GN', three =>'GIN', num => '324' },
			    'Guinea-Bissau'					   => { two => 'GW', three =>'GNB', num => '624' },
			    'Guyana'						   => { two => 'GY', three =>'GUY', num => '328' },
			    'Haiti'						   => { two => 'HT', three =>'HTI', num => '332' },
			    'Heard Island and McDonald Islands'			   => { two => 'HM', three =>'HMD', num => '334' },
			    'Holy See'						   => { two => 'VA', three =>'VAT', num => '336' },
			    'Honduras'						   => { two => 'HN', three =>'HND', num => '340' },
			    'Hong Kong'						   => { two => 'HK', three =>'HKG', num => '344' },
			    'Hungary'						   => { two => 'HU', three =>'HUN', num => '348' },
			    'Iceland'						   => { two => 'IS', three =>'ISL', num => '352' },
			    'India'						   => { two => 'IN', three =>'IND', num => '356' },
			    'Indonesia'						   => { two => 'ID', three =>'IDN', num => '360' },
			    'Iran (Islamic Republic of)'			   => { two => 'IR', three =>'IRN', num => '364' },
			    'Iraq'						   => { two => 'IQ', three =>'IRQ', num => '368' },
			    'Ireland'						   => { two => 'IE', three =>'IRL', num => '372' },
			    'Isle of Man'					   => { two => 'IM', three =>'IMN', num => '833' },
			    'Israel'						   => { two => 'IL', three =>'ISR', num => '376' },
			    'Italy'						   => { two => 'IT', three =>'ITA', num => '380' },
			    'Jamaica'						   => { two => 'JM', three =>'JAM', num => '388' },
			    'Japan'						   => { two => 'JP', three =>'JPN', num => '392' },
			    'Jersey'						   => { two => 'JE', three =>'JEY', num => '832' },
			    'Jordan'						   => { two => 'JO', three =>'JOR', num => '400' },
			    'Kazakhstan'					   => { two => 'KZ', three =>'KAZ', num => '398' },
			    'Kenya'						   => { two => 'KE', three =>'KEN', num => '404' },
			    'Kiribati'						   => { two => 'KI', three =>'KIR', num => '296' },
			    'Korea (Democratic People\'s Republic of)'		   => { two => 'KP', three =>'PRK', num => '408' },
			    'Korea (Republic of)'				   => { two => 'KR', three =>'KOR', num => '410' },
			    'Kuwait'						   => { two => 'KW', three =>'KWT', num => '414' },
			    'Kyrgyzstan'					   => { two => 'KG', three =>'KGZ', num => '417' },
			    'Lao People\'s Democratic Republic'			   => { two => 'LA', three =>'LAO', num => '418' },
			    'Latvia'						   => { two => 'LV', three =>'LVA', num => '428' },
			    'Lebanon'						   => { two => 'LB', three =>'LBN', num => '422' },
			    'Lesotho'						   => { two => 'LS', three =>'LSO', num => '426' },
			    'Liberia'						   => { two => 'LR', three =>'LBR', num => '430' },
			    'Libya'						   => { two => 'LY', three =>'LBY', num => '434' },
			    'Liechtenstein'					   => { two => 'LI', three =>'LIE', num => '438' },
			    'Lithuania'						   => { two => 'LT', three =>'LTU', num => '440' },
			    'Luxembourg'					   => { two => 'LU', three =>'LUX', num => '442' },
			    'Macao'						   => { two => 'MO', three =>'MAC', num => '446' },
			    'Macedonia (the former Yugoslav Republic of)'	   => { two => 'MK', three =>'MKD', num => '807' },
			    'Madagascar'					   => { two => 'MG', three =>'MDG', num => '450' },
			    'Malawi'						   => { two => 'MW', three =>'MWI', num => '454' },
			    'Malaysia'						   => { two => 'MY', three =>'MYS', num => '458' },
			    'Maldives'						   => { two => 'MV', three =>'MDV', num => '462' },
			    'Mali'						   => { two => 'ML', three =>'MLI', num => '466' },
			    'Malta'						   => { two => 'MT', three =>'MLT', num => '470' },
			    'Marshall Islands'					   => { two => 'MH', three =>'MHL', num => '584' },
			    'Martinique'					   => { two => 'MQ', three =>'MTQ', num => '474' },
			    'Mauritania'					   => { two => 'MR', three =>'MRT', num => '478' },
			    'Mauritius'						   => { two => 'MU', three =>'MUS', num => '480' },
			    'Mayotte'						   => { two => 'YT', three =>'MYT', num => '175' },
			    'Mexico'						   => { two => 'MX', three =>'MEX', num => '484' },
			    'Micronesia (Federated States of)'			   => { two => 'FM', three =>'FSM', num => '583' },
			    'Moldova (Republic of)'				   => { two => 'MD', three =>'MDA', num => '498' },
			    'Monaco'						   => { two => 'MC', three =>'MCO', num => '492' },
			    'Mongolia'						   => { two => 'MN', three =>'MNG', num => '496' },
			    'Montenegro'					   => { two => 'ME', three =>'MNE', num => '499' },
			    'Montserrat'					   => { two => 'MS', three =>'MSR', num => '500' },
			    'Morocco'						   => { two => 'MA', three =>'MAR', num => '504' },
			    'Mozambique'					   => { two => 'MZ', three =>'MOZ', num => '508' },
			    'Myanmar'						   => { two => 'MM', three =>'MMR', num => '104' },
			    'Namibia'						   => { two => 'NA', three =>'NAM', num => '516' },
			    'Nauru'						   => { two => 'NR', three =>'NRU', num => '520' },
			    'Nepal'						   => { two => 'NP', three =>'NPL', num => '524' },
			    'Netherlands'					   => { two => 'NL', three =>'NLD', num => '528' },
			    'New Caledonia'					   => { two => 'NC', three =>'NCL', num => '540' },
			    'New Zealand'					   => { two => 'NZ', three =>'NZL', num => '554' },
			    'Nicaragua'						   => { two => 'NI', three =>'NIC', num => '558' },
			    'Niger'						   => { two => 'NE', three =>'NER', num => '562' },
			    'Nigeria'						   => { two => 'NG', three =>'NGA', num => '566' },
			    'Niue'						   => { two => 'NU', three =>'NIU', num => '570' },
			    'Norfolk Island'					   => { two => 'NF', three =>'NFK', num => '574' },
			    'Northern Mariana Islands'				   => { two => 'MP', three =>'MNP', num => '580' },
			    'Norway'						   => { two => 'NO', three =>'NOR', num => '578' },
			    'Oman'						   => { two => 'OM', three =>'OMN', num => '512' },
			    'Pakistan'						   => { two => 'PK', three =>'PAK', num => '586' },
			    'Palau'						   => { two => 'PW', three =>'PLW', num => '585' },
			    'Palestine, State of'				   => { two => 'PS', three =>'PSE', num => '275' },
			    'Panama'						   => { two => 'PA', three =>'PAN', num => '591' },
			    'Papua New Guinea'					   => { two => 'PG', three =>'PNG', num => '598' },
			    'Paraguay'						   => { two => 'PY', three =>'PRY', num => '600' },
			    'Peru'						   => { two => 'PE', three =>'PER', num => '604' },
			    'Philippines'					   => { two => 'PH', three =>'PHL', num => '608' },
			    'Pitcairn'						   => { two => 'PN', three =>'PCN', num => '612' },
			    'Poland'						   => { two => 'PL', three =>'POL', num => '616' },
			    'Portugal'						   => { two => 'PT', three =>'PRT', num => '620' },
			    'Puerto Rico'					   => { two => 'PR', three =>'PRI', num => '630' },
			    'Qatar'						   => { two => 'QA', three =>'QAT', num => '634' },
			    'Réunion'						   => { two => 'RE', three =>'REU', num => '638' },
			    'Romania'						   => { two => 'RO', three =>'ROU', num => '642' },
			    'Russian Federation'				   => { two => 'RU', three =>'RUS', num => '643' },
			    'Rwanda'						   => { two => 'RW', three =>'RWA', num => '646' },
			    'Saint Barthélemy'					   => { two => 'BL', three =>'BLM', num => '652' },
			    'Saint Helena Ascension and Tristan da Cunha'	   => { two => 'SH', three =>'SHN', num => '654' },
			    'Saint Kitts and Nevis'				   => { two => 'KN', three =>'KNA', num => '659' },
			    'Saint Lucia'					   => { two => 'LC', three =>'LCA', num => '662' },
			    'Saint Martin (French part)'			   => { two => 'MF', three =>'MAF', num => '663' },
			    'Saint Pierre and Miquelon'				   => { two => 'PM', three =>'SPM', num => '666' },
			    'Saint Vincent and the Grenadines'			   => { two => 'VC', three =>'VCT', num => '670' },
			    'Samoa'						   => { two => 'WS', three =>'WSM', num => '882' },
			    'San Marino'					   => { two => 'SM', three =>'SMR', num => '674' },
			    'Sao Tome and Principe'				   => { two => 'ST', three =>'STP', num => '678' },
			    'Saudi Arabia'					   => { two => 'SA', three =>'SAU', num => '682' },
			    'Senegal'						   => { two => 'SN', three =>'SEN', num => '686' },
			    'Serbia'						   => { two => 'RS', three =>'SRB', num => '688' },
			    'Seychelles'					   => { two => 'SC', three =>'SYC', num => '690' },
			    'Sierra Leone'					   => { two => 'SL', three =>'SLE', num => '694' },
			    'Singapore'						   => { two => 'SG', three =>'SGP', num => '702' },
			    'Sint Maarten (Dutch part)'				   => { two => 'SX', three =>'SXM', num => '534' },
			    'Slovakia'						   => { two => 'SK', three =>'SVK', num => '703' },
			    'Slovenia'						   => { two => 'SI', three =>'SVN', num => '705' },
			    'Solomon Islands'					   => { two => 'SB', three =>'SLB', num => '090' },
			    'Somalia'						   => { two => 'SO', three =>'SOM', num => '706' },
			    'South Africa'					   => { two => 'ZA', three =>'ZAF', num => '710' },
			    'South Georgia and the South Sandwich Islands'	   => { two => 'GS', three =>'SGS', num => '239' },
			    'South Sudan'					   => { two => 'SS', three =>'SSD', num => '728' },
			    'Spain'						   => { two => 'ES', three =>'ESP', num => '724' },
			    'Sri Lanka'						   => { two => 'LK', three =>'LKA', num => '144' },
			    'Sudan'						   => { two => 'SD', three =>'SDN', num => '729' },
			    'Suriname'						   => { two => 'SR', three =>'SUR', num => '740' },
			    'Svalbard and Jan Mayen'				   => { two => 'SJ', three =>'SJM', num => '744' },
			    'Eswatini'						   => { two => 'SZ', three =>'SWZ', num => '748' },
			    'Sweden'						   => { two => 'SE', three =>'SWE', num => '752' },
			    'Switzerland'					   => { two => 'CH', three =>'CHE', num => '756' },
			    'Syrian Arab Republic'				   => { two => 'SY', three =>'SYR', num => '760' },
			    'Taiwan'						   => { two => 'TW', three =>'TWN', num => '158' },
			    'Tajikistan'					   => { two => 'TJ', three =>'TJK', num => '762' },
			    'Tanzania United Republic of'			   => { two => 'TZ', three =>'TZA', num => '834' },
			    'Thailand'						   => { two => 'TH', three =>'THA', num => '764' },
			    'Timor-Leste'					   => { two => 'TL', three =>'TLS', num => '626' },
			    'Togo'						   => { two => 'TG', three =>'TGO', num => '768' },
			    'Tokelau'						   => { two => 'TK', three =>'TKL', num => '772' },
			    'Tonga'						   => { two => 'TO', three =>'TON', num => '776' },
			    'Trinidad and Tobago'				   => { two => 'TT', three =>'TTO', num => '780' },
			    'Tunisia'						   => { two => 'TN', three =>'TUN', num => '788' },
			    'Turkey'						   => { two => 'TR', three =>'TUR', num => '792' },
			    'Turkmenistan'					   => { two => 'TM', three =>'TKM', num => '795' },
			    'Turks and Caicos Islands'				   => { two => 'TC', three =>'TCA', num => '796' },
			    'Tuvalu'						   => { two => 'TV', three =>'TUV', num => '798' },
			    'Uganda'						   => { two => 'UG', three =>'UGA', num => '800' },
			    'Ukraine'						   => { two => 'UA', three =>'UKR', num => '804' },
			    'United Arab Emirates'				   => { two => 'AE', three =>'ARE', num => '784' },
			    'United Kingdom of Great Britain and Northern Ireland' => { two => 'GB', three =>'GBR', num => '826' },
			    'United States of America'				   => { two => 'US', three =>'USA', num => '840' },
			    'United States Minor Outlying Islands'		   => { two => 'UM', three =>'UMI', num => '581' },
			    'Uruguay'						   => { two => 'UY', three =>'URY', num => '858' },
			    'Uzbekistan'					   => { two => 'UZ', three =>'UZB', num => '860' },
			    'Vanuatu'						   => { two => 'VU', three =>'VUT', num => '548' },
			    'Venezuela, Bolivarian Republic of'			   => { two => 'VE', three =>'VEN', num => '862' },
			    'Viet Nam'						   => { two => 'VN', three =>'VNM', num => '704' },
			    'Virgin Islands (British)'				   => { two => 'VG', three =>'VGB', num => '092' },
			    'Virgin Islands (U.S.)'				   => { two => 'VI', three =>'VIR', num => '850' },
			    'Wallis and Futuna'					   => { two => 'WF', three =>'WLF', num => '876' },
			    'Western Sahara'					   => { two => 'EH', three =>'ESH', num => '732' },
			    'Yemen'						   => { two => 'YE', three =>'YEM', num => '887' },
			    'Zambia'						   => { two => 'ZM', three =>'ZMB', num => '894' },
			    'Zimbabwe'                                             => { two => 'ZW', three =>'ZWE', num => '716' },
			   },
	      LDAP => {
		       # The reqResult attribute is the numeric LDAP result
		       # code of the operation, indicating either success or
		       # a particular LDAP error code.
		       # Net::LDAP::Constant(3) -> Protoco Constants
		       #
		       # as variant ??:
		       #
		       # use Net::LDAP::Constant;
		       # use strict;
		       # use warnings;
		       # use Data::Printer;
		       # # Get all constants defined in the package
		       # my @protocol_constants = grep {
		       #     defined(&{"Net::LDAP::Constant::$_"}) &&
		       #     $_ =~ /^(LDAP|LDAP_SCOPE|LDAP_AUTH|LDAP_VERSION|LDAP_SUCCESS|LDAP_OTHER)/
		       # } keys %Net::LDAP::Constant::;
		       # my %c;
		       # foreach my $const (@protocol_constants) {
		       #     no strict 'refs';
		       #     my $val = &{"Net::LDAP::Constant::$const"}();
		       #     $c{$val} = $const if $val =~ /^[[:digit:]]+$/;
		       # }
		       # p %c;
		       PROTOCOL => {
				    0    =>    '0 - LDAP_SUCCESS',
				    1    =>    '1 - LDAP_OPERATIONS_ERROR',
				    2    =>    '2 - LDAP_PROTOCOL_ERROR',
				    3    =>    '3 - LDAP_TIMELIMIT_EXCEEDED',
				    4    =>    '4 - LDAP_SIZELIMIT_EXCEEDED',
				    5    =>    '5 - LDAP_COMPARE_FALSE',
				    6    =>    '6 - LDAP_COMPARE_TRUE',
				    7    =>    '7 - LDAP_AUTH_METHOD_NOT_SUPPORTED',
				    7    =>    '7 - LDAP_STRONG_AUTH_NOT_SUPPORTED',
				    8    =>    '8 - LDAP_STRONG_AUTH_REQUIRED',
				    9    =>    '9 - LDAP_PARTIAL_RESULTS',
				    10   =>   '10 - LDAP_REFERRAL',
				    11   =>   '11 - LDAP_ADMIN_LIMIT_EXCEEDED',
				    12   =>   '12 - LDAP_UNAVAILABLE_CRITICAL_EXT',
				    13   =>   '13 - LDAP_CONFIDENTIALITY_REQUIRED',
				    14   =>   '14 - LDAP_SASL_BIND_IN_PROGRESS',
				    16   =>   '16 - LDAP_NO_SUCH_ATTRIBUTE',
				    17   =>   '17 - LDAP_UNDEFINED_TYPE',
				    18   =>   '18 - LDAP_INAPPROPRIATE_MATCHING',
				    19   =>   '19 - LDAP_CONSTRAINT_VIOLATION',
				    20   =>   '20 - LDAP_TYPE_OR_VALUE_EXISTS',
				    21   =>   '21 - LDAP_INVALID_SYNTAX',
				    32   =>   '32 - LDAP_NO_SUCH_OBJECT',
				    33   =>   '33 - LDAP_ALIAS_PROBLEM',
				    34   =>   '34 - LDAP_INVALID_DN_SYNTAX',
				    35   =>   '35 - LDAP_IS_LEAF',
				    36   =>   '36 - LDAP_ALIAS_DEREF_PROBLEM',
				    47   =>   '47 - LDAP_PROXY_AUTHZ_FAILURE',
				    48   =>   '48 - LDAP_INAPPROPRIATE_AUTH',
				    49   =>   '49 - LDAP_INVALID_CREDENTIALS',
				    50   =>   '50 - LDAP_INSUFFICIENT_ACCESS',
				    51   =>   '51 - LDAP_BUSY',
				    52   =>   '52 - LDAP_UNAVAILABLE',
				    53   =>   '53 - LDAP_UNWILLING_TO_PERFORM',
				    54   =>   '54 - LDAP_LOOP_DETECT',
				    60   =>   '60 - LDAP_SORT_CONTROL_MISSING',
				    61   =>   '61 - LDAP_INDEX_RANGE_ERROR',
				    64   =>   '64 - LDAP_NAMING_VIOLATION',
				    65   =>   '65 - LDAP_OBJECT_CLASS_VIOLATION',
				    66   =>   '66 - LDAP_NOT_ALLOWED_ON_NONLEAF',
				    67   =>   '67 - LDAP_NOT_ALLOWED_ON_RDN',
				    68   =>   '68 - LDAP_ALREADY_EXISTS',
				    69   =>   '69 - LDAP_NO_OBJECT_CLASS_MODS',
				    70   =>   '70 - LDAP_RESULTS_TOO_LARGE',
				    71   =>   '71 - LDAP_AFFECTS_MULTIPLE_DSAS',
				    76   =>   '76 - LDAP_VLV_ERROR',
				    80   =>   '80 - LDAP_OTHER',
				    81   =>   '81 - LDAP_SERVER_DOWN',
				    82   =>   '82 - LDAP_LOCAL_ERROR',
				    83   =>   '83 - LDAP_ENCODING_ERROR',
				    84   =>   '84 - LDAP_DECODING_ERROR',
				    85   =>   '85 - LDAP_TIMEOUT',
				    86   =>   '86 - LDAP_AUTH_UNKNOWN',
				    87   =>   '87 - LDAP_FILTER_ERROR',
				    88   =>   '88 - LDAP_USER_CANCELED',
				    89   =>   '89 - LDAP_PARAM_ERROR',
				    90   =>   '90 - LDAP_NO_MEMORY',
				    91   =>   '91 - LDAP_CONNECT_ERROR',
				    92   =>   '92 - LDAP_NOT_SUPPORTED',
				    93   =>   '93 - LDAP_CONTROL_NOT_FOUND',
				    94   =>   '94 - LDAP_NO_RESULTS_RETURNED',
				    95   =>   '95 - LDAP_MORE_RESULTS_TO_RETURN',
				    96   =>   '96 - LDAP_CLIENT_LOOP',
				    97   =>   '97 - LDAP_REFERRAL_LIMIT_EXCEEDED',
				    118  =>  '118 - LDAP_CANCELED',
				    119  =>  '119 - LDAP_NO_SUCH_OPERATION',
				    120  =>  '120 - LDAP_TOO_LATE',
				    121  =>  '121 - LDAP_CANNOT_CANCEL',
				    122  =>  '122 - LDAP_ASSERTION_FAILED',
				    4096 => '4096 - LDAP_SYNC_REFRESH_REQUIRED',
				   },
		      },
	      TRANSLIT => {
			   # Russian Cyrillic
			   'А' => 'A',   'а' => 'a',
			   'Б' => 'B',   'б' => 'b',
			   'В' => 'V',   'в' => 'v',
			   'Г' => 'G',   'г' => 'g',
			   'Д' => 'D',   'д' => 'd',
			   'Е' => 'E',   'е' => 'e',
			   'Ё' => 'Yo',  'ё' => 'yo',
			   'Ж' => 'Zh',  'ж' => 'zh',
			   'З' => 'Z',   'з' => 'z',
			   'И' => 'I',   'и' => 'i',
			   'Й' => 'Y',   'й' => 'y',
			   'К' => 'K',   'к' => 'k',
			   'Л' => 'L',   'л' => 'l',
			   'М' => 'M',   'м' => 'm',
			   'Н' => 'N',   'н' => 'n',
			   'О' => 'O',   'о' => 'o',
			   'П' => 'P',   'п' => 'p',
			   'Р' => 'R',   'р' => 'r',
			   'С' => 'S',   'с' => 's',
			   'Т' => 'T',   'т' => 't',
			   'У' => 'U',   'у' => 'u',
			   'Ф' => 'F',   'ф' => 'f',
			   'Х' => 'Kh',  'х' => 'kh',
			   'Ц' => 'Ts',  'ц' => 'ts',
			   'Ч' => 'Ch',  'ч' => 'ch',
			   'Ш' => 'Sh',  'ш' => 'sh',
			   'Щ' => 'Shch', 'щ' => 'shch',
			   'Ъ' => '',    'ъ' => '',
			   'Ы' => 'Y',   'ы' => 'y',
			   'Ь' => '',    'ь' => '',
			   'Э' => 'E',   'э' => 'e',
			   'Ю' => 'Yu',  'ю' => 'yu',
			   'Я' => 'Ya',  'я' => 'ya',

			   # Ukrainian specific
			   'Ґ' => 'G',   'ґ' => 'g',
			   'Є' => 'Ye',  'є' => 'ye',
			   'І' => 'I',   'і' => 'i',
			   'Ї' => 'Yi',  'ї' => 'yi',

			   # Belarusian specific
			   'Ў' => 'U',   'ў' => 'u',

			   # Serbian/Macedonian/Bulgarian specific
			   'Ђ' => 'Dj',  'ђ' => 'dj',
			   'Ј' => 'J',   'ј' => 'j',
			   'Љ' => 'Lj',  'љ' => 'lj',
			   'Њ' => 'Nj',  'њ' => 'nj',
			   'Ћ' => 'C',   'ћ' => 'c',
			   'Џ' => 'Dz',  'џ' => 'dz',

			   # FRENCH - Accented letters
			   'À' => 'A',   'à' => 'a', # A with grave
			   'Á' => 'A',   'á' => 'a', # A with acute
			   'Â' => 'A',   'â' => 'a', # A with circumflex
			   'Ã' => 'A',   'ã' => 'a', # A with tilde
			   'Ä' => 'A',   'ä' => 'a', # A with diaeresis
			   'Å' => 'A',   'å' => 'aa', # A with ring
			   'Æ' => 'AE',  'æ' => 'ae', # AE ligature
			   'Ç' => 'C',   'ç' => 'c',  # C with cedilla
			   'È' => 'E',   'è' => 'e',  # E with grave
			   'É' => 'E',   'é' => 'e',  # E with acute
			   'Ê' => 'E',   'ê' => 'e',  # E with circumflex
			   'Ë' => 'E',   'ë' => 'e',  # E with diaeresis
			   'Ì' => 'I',   'ì' => 'i',  # I with grave
			   'Í' => 'I',   'í' => 'i',  # I with acute
			   'Î' => 'I',   'î' => 'i',  # I with circumflex
			   'Ï' => 'I',   'ï' => 'i',  # I with diaeresis
			   'Ñ' => 'N',   'ñ' => 'n',  # N with tilde
			   'Ò' => 'O',   'ò' => 'o',  # O with grave
			   'Ó' => 'O',   'ó' => 'o',  # O with acute
			   'Ô' => 'O',   'ô' => 'o',  # O with circumflex
			   'Õ' => 'O',   'õ' => 'o',  # O with tilde
			   'Ö' => 'O',   'ö' => 'oe', # O with diaeresis
			   'Ø' => 'O',   'ø' => 'o',  # O with stroke
			   'Œ' => 'OE',  'œ' => 'oe', # OE ligature
			   'Ù' => 'U',   'ù' => 'u',  # U with grave
			   'Ú' => 'U',   'ú' => 'u',  # U with acute
			   'Û' => 'U',   'û' => 'u',  # U with circumflex
			   'Ü' => 'U',   'ü' => 'u',  # U with diaeresis
			   'Ý' => 'Y',   'ý' => 'y',  # Y with acute
			   'Ÿ' => 'Y',   'ÿ' => 'y',  # Y with diaeresis

			   # SPANISH specific
			   'Ñ' => 'N',   'ñ' => 'n', # N with tilde (already above)
			   '¿' => '',    '¡' => '', # Inverted question/exclamation marks

			   # PORTUGUESE specific
			   'Ã' => 'A',   'ã' => 'a', # A with tilde (already above)
			   'Õ' => 'O',   'õ' => 'o', # O with tilde (already above)

			   # GERMAN specific
			   'Ä' => 'Ae',  'ä' => 'ae', # A with diaeresis (umlaut) - German style
			   'Ö' => 'Oe',  'ö' => 'oe', # O with diaeresis (umlaut) - German style
			   'Ü' => 'Ue',  'ü' => 'ue', # U with diaeresis (umlaut) - German style
			   'ß' => 'ss',               # Eszett (sharp s)

			   # NORWEGIAN/DANISH specific
			   'Å' => 'A',   'å' => 'a', # A with ring (already above)
			   'Æ' => 'AE',  'æ' => 'ae', # AE ligature (already above)
			   'Ø' => 'O',   'ø' => 'o', # O with stroke (already above)

			   # SWEDISH specific (same as Norwegian for most)
			   # Already covered above

			   # POLISH specific
			   'Ą' => 'A',   'ą' => 'a', # A with ogonek
			   'Ć' => 'C',   'ć' => 'c', # C with acute
			   'Ę' => 'E',   'ę' => 'e', # E with ogonek
			   'Ł' => 'L',   'ł' => 'l', # L with stroke
			   'Ń' => 'N',   'ń' => 'n', # N with acute
			   'Ó' => 'O',   'ó' => 'o', # O with acute (already above)
			   'Ś' => 'S',   'ś' => 's', # S with acute
			   'Ź' => 'Z',   'ź' => 'z', # Z with acute
			   'Ż' => 'Z',   'ż' => 'z', # Z with dot above

			   # CZECH specific
			   'Á' => 'A',   'á' => 'a', # A with acute (already above)
			   'Č' => 'C',   'č' => 'c', # C with caron
			   'Ď' => 'D',   'ď' => 'd', # D with caron
			   'É' => 'E',   'é' => 'e', # E with acute (already above)
			   'Ě' => 'E',   'ě' => 'e', # E with caron
			   'Í' => 'I',   'í' => 'i', # I with acute (already above)
			   'Ň' => 'N',   'ň' => 'n', # N with caron
			   'Ó' => 'O',   'ó' => 'o', # O with acute (already above)
			   'Ř' => 'R',   'ř' => 'r', # R with caron
			   'Š' => 'S',   'š' => 's', # S with caron
			   'Ť' => 'T',   'ť' => 't', # T with caron
			   'Ú' => 'U',   'ú' => 'u', # U with acute (already above)
			   'Ů' => 'U',   'ů' => 'u', # U with ring
			   'Ý' => 'Y',   'ý' => 'y', # Y with acute (already above)
			   'Ž' => 'Z',   'ž' => 'z', # Z with caron

			   # SLOVAK specific (similar to Czech)
			   'Ä' => 'A',   'ä' => 'a', # A with diaeresis (already above)
			   'Ĺ' => 'L',   'ĺ' => 'l', # L with acute
			   'Ľ' => 'L',   'ľ' => 'l', # L with caron
			   'Ô' => 'O',   'ô' => 'o', # O with circumflex (already above)
			   'Ŕ' => 'R',   'ŕ' => 'r', # R with acute

			   # HUNGARIAN specific
			   'Á' => 'A',   'á' => 'a', # A with acute (already above)
			   'É' => 'E',   'é' => 'e', # E with acute (already above)
			   'Í' => 'I',   'í' => 'i', # I with acute (already above)
			   'Ó' => 'O',   'ó' => 'o', # O with acute (already above)
			   'Ö' => 'O',   'ö' => 'o', # O with diaeresis (already above)
			   'Ő' => 'O',   'ő' => 'o', # O with double acute
			   'Ú' => 'U',   'ú' => 'u', # U with acute (already above)
			   'Ü' => 'U',   'ü' => 'u', # U with diaeresis (already above)
			   'Ű' => 'U',   'ű' => 'u', # U with double acute

			   # ROMANIAN specific
			   'Ă' => 'A',   'ă' => 'a', # A with breve
			   'Â' => 'A',   'â' => 'a', # A with circumflex (already above)
			   'Î' => 'I',   'î' => 'i', # I with circumflex (already above)
			   'Ș' => 'S',   'ș' => 's', # S with comma below
			   'Ț' => 'T',   'ț' => 't', # T with comma below

			   # ITALIAN specific
			   'À' => 'A',   'à' => 'a', # A with grave (already above)
			   'È' => 'E',   'è' => 'e', # E with grave (already above)
			   'É' => 'E',   'é' => 'e', # E with acute (already above)
			   'Ì' => 'I',   'ì' => 'i', # I with grave (already above)
			   'Í' => 'I',   'í' => 'i', # I with acute (already above)
			   'Ò' => 'O',   'ò' => 'o', # O with grave (already above)
			   'Ó' => 'O',   'ó' => 'o', # O with acute (already above)
			   'Ù' => 'U',   'ù' => 'u', # U with grave (already above)
			   'Ú' => 'U',   'ú' => 'u', # U with acute (already above)

			   # DUTCH specific
			   'IJ' => 'IJ', 'ij' => 'ij', # IJ ligature
			   'Ĳ' => 'IJ',  'ĳ' => 'ij', # IJ ligature (Unicode)

			   # TURKISH specific
			   'Ç' => 'C',   'ç' => 'c', # C with cedilla (already above)
			   'Ğ' => 'G',   'ğ' => 'g', # G with breve
			   'İ' => 'I',   'ı' => 'i', # I with dot / dotless i
			   'Ö' => 'O',   'ö' => 'o', # O with diaeresis (already above)
			   'Ş' => 'S',   'ş' => 's', # S with cedilla
			   'Ü' => 'U',   'ü' => 'u', # U with diaeresis (already above)

			   # ICELANDIC specific
			   'Á' => 'A',   'á' => 'a', # A with acute (already above)
			   'Ð' => 'D',   'ð' => 'd', # Eth
			   'É' => 'E',   'é' => 'e', # E with acute (already above)
			   'Í' => 'I',   'í' => 'i', # I with acute (already above)
			   'Ó' => 'O',   'ó' => 'o', # O with acute (already above)
			   'Ú' => 'U',   'ú' => 'u', # U with acute (already above)
			   'Ý' => 'Y',   'ý' => 'y', # Y with acute (already above)
			   'Þ' => 'Th',  'þ' => 'th', # Thorn
			   'Æ' => 'AE',  'æ' => 'ae', # AE ligature (already above)
			   'Ø' => 'O',   'ø' => 'o', # O with stroke (already above)

			   # FINNISH specific (similar to Swedish/Norwegian)
			   'Ä' => 'A',   'ä' => 'a', # A with diaeresis (already above)
			   'Ö' => 'O',   'ö' => 'o', # O with diaeresis (already above)
			   'Å' => 'A',   'å' => 'a', # A with ring (already above)

			   # ESTONIAN specific
			   'Ä' => 'A',   'ä' => 'a', # A with diaeresis (already above)
			   'Ö' => 'O',   'ö' => 'o', # O with diaeresis (already above)
			   'Ü' => 'U',   'ü' => 'u', # U with diaeresis (already above)
			   'Õ' => 'O',   'õ' => 'o', # O with tilde (already above)

			   # LATVIAN specific
			   'Ā' => 'A',   'ā' => 'a', # A with macron
			   'Č' => 'C',   'č' => 'c', # C with caron (already above)
			   'Ē' => 'E',   'ē' => 'e', # E with macron
			   'Ģ' => 'G',   'ģ' => 'g', # G with cedilla
			   'Ī' => 'I',   'ī' => 'i', # I with macron
			   'Ķ' => 'K',   'ķ' => 'k', # K with cedilla
			   'Ļ' => 'L',   'ļ' => 'l', # L with cedilla
			   'Ņ' => 'N',   'ņ' => 'n', # N with cedilla
			   'Š' => 'S',   'š' => 's', # S with caron (already above)
			   'Ū' => 'U',   'ū' => 'u', # U with macron
			   'Ž' => 'Z',   'ž' => 'z', # Z with caron (already above)

			   # LITHUANIAN specific
			   'Ą' => 'A',   'ą' => 'a', # A with ogonek (already above)
			   'Č' => 'C',   'č' => 'c', # C with caron (already above)
			   'Ę' => 'E',   'ę' => 'e', # E with ogonek (already above)
			   'Ė' => 'E',   'ė' => 'e', # E with dot above
			   'Į' => 'I',   'į' => 'i', # I with ogonek
			   'Š' => 'S',   'š' => 's', # S with caron (already above)
			   'Ų' => 'U',   'ų' => 'u', # U with ogonek
			   'Ū' => 'U',   'ū' => 'u', # U with macron (already above)
			   'Ž' => 'Z',   'ž' => 'z', # Z with caron (already above)

			   # MALTESE specific
			   'Ċ' => 'C',   'ċ' => 'c', # C with dot above
			   'Ġ' => 'G',   'ġ' => 'g', # G with dot above
			   'Ħ' => 'H',   'ħ' => 'h', # H with stroke
			   'Ż' => 'Z',   'ż' => 'z', # Z with dot above (already above)

			   # WELSH specific
			   'Â' => 'A',   'â' => 'a', # A with circumflex (already above)
			   'Ê' => 'E',   'ê' => 'e', # E with circumflex (already above)
			   'Î' => 'I',   'î' => 'i', # I with circumflex (already above)
			   'Ô' => 'O',   'ô' => 'o', # O with circumflex (already above)
			   'Û' => 'U',   'û' => 'u', # U with circumflex (already above)
			   'Ŵ' => 'W',   'ŵ' => 'w', # W with circumflex
			   'Ŷ' => 'Y',   'ŷ' => 'y', # Y with circumflex

			   # LEGACY ENTRIES (from original)
			   '′' => '',
			   'Ǵ' => 'g',  'ǵ' => 'g', # G with acute
			  },
	     };

1;
