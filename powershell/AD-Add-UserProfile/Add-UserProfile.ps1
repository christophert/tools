#Requires -Version 4.0
#Requires -RunAsAdministrator
# Create Local Profile for AD User

## define Win32 API function
function Create-UserProfile {
    <#
        .SYNOPSIS
            Creates a user profile for a domain user using the Win32 USERENV API.
            This allows system administrators to add users to new machines without
            requiring the user to be present. This allows administrators to restore
            profiles before a machine is delivered to a user.

        .EXAMPLE
            Create-UserProfile -UserSid S-1-5-21-12345678-12341234512-9999 -UserName user.name
        .NOTES
            Christopher Tran
            code@christran.in
        .LINK
            https://github.com/christophert/tools/powershell/AD-Add-UserProfile
    #>
    Param (
        # Account SID
        [String] $UserSid,

        # Account Username (without domain)
        [String] $UserName
    )

    $MethodDefinition = @"
        [DllImport("userenv.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern int CreateProfile(
            [MarshalAs(UnmanagedType.LPWStr)] String pszUserSid,
            [MarshalAs(UnmanagedType.LPWStr)] String pszUserName,
            [Out, MarshalAs(UnmanagedType.LPWStr)] System.Text.StringBuilder pszProfilePath,
            UInt32 cchProfilePath
        );
"@

    # Register method definition to the current session
    $Userenv = Add-Type -MemberDefinition $MethodDefinition -Name 'CreateUserProfile' -Namespace 'UserProfile' -UsingNamespace "System.Security.Principal" -PassThru

    # build empty buffer for the user profile path to populate
    $userProfilePath = New-Object System.Text.StringBuilder(260)
    $CreateResult = $Userenv::CreateProfile($UserSid, $UserName, $userProfilePath, $userProfilePath.Capacity)

    if($CreateResult -ne 0) {
        $exp = [System.Runtime.InteropServices.Marshal]::GetExceptionForHR($CreateResult)

        # Handle error codes
        Switch($CreateResult) {
            0x800700b7 { Write-Error "E_ALREADY_EXISTS - Profile already exists on machine." }
            0x80070005 { Write-Error "E_ACCESSDENIED - Access is denied." }
        }
        exit 1
    } else {
        Write-Host "Profile has been created!"
        Write-Host "Profile location: $($userProfilePath)"
    }
}

Do {
    Do {
        $dom = Read-Host -Prompt 'Enter Domain'
        $user = Read-Host -Prompt 'Enter Username'
        $userObj = New-Object System.Security.Principal.NTAccount($dom + '\' + $user)
        try {
            $userSID = ($userObj.Translate([System.Security.Principal.SecurityIdentifier])).Value
        }
        catch [System.Security.Principal.IdentityNotMappedException] {
            Write-Host "Unable to find user in domain!"
            Continue
        }
    } While ([string]::IsNullOrWhiteSpace($userSID))

    Write-Host "User $($dom + '\' + $user) with SID $userSID has been staged."

    $confirm = Read-Host -Prompt 'Are you sure you want to create this profile? (Y/N)'
    if($confirm.ToUpper() -eq "Y") {
        Write-Host "Attempting to create profile for $user with SID $userSID"
        Create-UserProfile -UserSid $userSID -UserName $user -UserProfilePath $userProfilePath
    } else {
        Write-Host "Aborting."
        exit 1
    }

    $another = Read-Host -Prompt 'Add another user? (y/N)'
    if([string]::IsNullOrWhiteSpace($done)) {
        $another = 'N'
    }
} While ($another.ToUpper() -eq "Y")
