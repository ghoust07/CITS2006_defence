rule hidden_files
{
    meta:
        description = "Detects hidden files containing sensitive information"
        author = "AATRO"
    strings:
        $hidden = /\.[a-zA-Z0-9]+/ nocase
        $sensitive1 = "password" nocase
        $sensitive2 = "secret" nocase
        $sensitive3 = "confidential" nocase
        $sensitive4 = "key" nocase
    condition:
        file_name matches $hidden and any of ($sensitive1, $sensitive2, $sensitive3, $sensitive4)
}


