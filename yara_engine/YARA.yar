rule malware
{
	meta:
		description = "any files determined to be malware"
		author = "AATRO"
	strings:
		//strings go here
	condition:
		//conditions go here
	//TODO: detect common malware tricks (masking extension), detect well-known malware? Cross-reference with database?
}

rule hidden_files
{
	meta:
		description = "any files that have been hidden but not encrypted"
		author = "AATRO"
	strings:
		$hidden = \.[.]+\.[a-z]{2,} nocase
	condition:
		file_name == $hidden
	//TODO: detect if file is not encrypted, detect if file contains sensitive info?
}

rule scripts
{
	meta:
		description = "any detected scripts"
		author = "AATRO"
	strings:
		//strings go here
	condition:
		//conditions go here
	//TODO: detect scripts
}

rule network_executables
{
	meta:
		description = "any executables which access network resources"
		author = "AATRO"
	strings:
		//strings go here
	condition:
		uint32(0) == 0x7F454C46
	//TODO: detect attempted network access
}

rule urls
{
	meta:
		description = "any executables which try to access malicious URLs"
		author = "AATRO"
	strings:
		$url = /http[s]?:\/\/[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}\/[a-zA-Z0-9\/%&=\?_\-\.]+/ nocase
	condition:
		uint32(0) == 0x7F454C46 and $url
	//TODO: detect if URL is malicious with VirusTotal?
}

rule custom_signatures
{
	meta:
		description = "any files which contain custom signatures"
		author = "AATRO"
	strings:
		//strings go here
	condition:
		//conditions go here
	//TODO: determine what signatures need detecting (and detect them)
}