#Set-Location -Path "C:\"
#. ((Split-Path -Path (Get-Module -Name posh-git -ListAvailable).Path -Parent)+"\profile.example.ps1")
Import-Module posh-git

<#

function Set-ConsoleOpacity {
    param(
        [ValidateRange(10, 100)]
        [int]$Opacity
    )

    # Check if pinvoke type already exists, if not import the relevant functions
    try {
        $Win32Type = [Win32.WindowLayer]
    }
    catch {
        $Win32Type = Add-Type -MemberDefinition @'
            [DllImport("user32.dll")]
            public static extern int SetWindowLong(IntPtr hWnd, int nIndex, int dwNewLong);

            [DllImport("user32.dll")]
            public static extern int GetWindowLong(IntPtr hWnd, int nIndex);

            [DllImport("user32.dll")]
            public static extern bool SetLayeredWindowAttributes(IntPtr hwnd, uint crKey, byte bAlpha, uint dwFlags);
'@ -Name WindowLayer -Namespace Win32 -PassThru
    }

    # Calculate opacity value (0-255)
    $OpacityValue = [int]($Opacity * 2.56) - 1

    # Grab the host windows handle
    $ThisProcess = Get-Process -Id $PID
    $WindowHandle = $ThisProcess.MainWindowHandle

    # "Constants"
    $GwlExStyle = -20;
    $WsExLayered = 0x80000;
    $LwaAlpha = 0x2;

    if ($Win32Type::GetWindowLong($WindowHandle, -20) -band $WsExLayered -ne $WsExLayered) {
        # If Window isn't already marked "Layered", make it so
        [void]$Win32Type::SetWindowLong($WindowHandle, $GwlExStyle, $Win32Type::GetWindowLong($WindowHandle, $GwlExStyle) -bxor $WsExLayered)
    }

    # Set transparency
    [void]$Win32Type::SetLayeredWindowAttributes($WindowHandle, 0, $OpacityValue, $LwaAlpha)
}

#>

function Global:Set-Title {

    if ($Host.Name -match "console") {
        #$MaxHeight = $host.UI.RawUI.MaxPhysicalWindowSize.Height
        #$MaxWidth = $host.UI.RawUI.MaxPhysicalWindowSize.Width

        #$MyBuffer = $Host.UI.RawUI.BufferSize
        #$MyWindow = $Host.UI.RawUI.WindowSize

        #$MyWindow.Height = ($MaxHeight)
        #$MyWindow.Width = ($Maxwidth-2)

        #$MyBuffer.Height = (9999)
        #$MyBuffer.Width = ($Maxwidth-2)

        #$host.UI.RawUI.set_bufferSize($MyBuffer)
        #$host.UI.RawUI.set_windowSize($MyWindow)



       }

    $CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $CurrentUserPrincipal = New-Object Security.Principal.WindowsPrincipal $CurrentUser
    $Adminrole = [Security.Principal.WindowsBuiltinRole]::Administrator
    If (($CurrentUserPrincipal).IsInRole($AdminRole)){$Elevated = "Administrator"}

    $Title = $Elevated + " $ENV:USERNAME".ToUpper() + ": $($Host.Name) "  + " - " + (Get-Date).toshortdatestring()
    $Host.UI.RawUI.set_WindowTitle($Title)

}

function Enter-ElevatedPSSession {
    #requires -Version 2.0

    <#
    .SYNOPSIS
        Enters a new elevated powershell process.

    .DESCRIPTION
        Enters a new elevated powershell process. You can optionally close your existing session.

    .PARAMETER CloseExisting
        If specified, the existing powershell session will be closed.

    .NOTES
        UAC will prompt you if it is enabled.

        Starts new administrative session.

        Will do nothing if you are already running elevated.

    .EXAMPLE
        # Running as normal user
        C:\Users\Joe> Enter-ElevatedPSSession
        # Starts new PowerShell process / session as administrator, keeping current session open.

    .EXAMPLE
        # Running as normal user
        C:\Users\Joe> Enter-ElevatedPSSession -CloseExisting
        # Starts new PowerShell process / session as administrator, exiting the current session.

    .EXAMPLE
        # Running already as administrator
        C:\Windows\System32> Enter-ElevatedPSSession
        Already running as administrator.
        # Message is written to host.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false,
                   Position=0)]
        [Alias('c')]
        [switch]
        $CloseExisting
    )
    begin {
        $runningProcess = 'powershell'
        if ((Get-Process -Id $pid).Name -eq 'powershell_ise') {
            $runningProcess = 'powershell_ise'
        }
        $Identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $Principal = New-Object System.Security.Principal.WindowsPrincipal($Identity)
        $isAdmin = $Principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    process {
        if ($isAdmin) {
            Write-Host -Object "Already running as administrator."
            return
        }
        if ($CloseExisting.IsPresent) {
            Start-Process $runningProcess -Verb RunAs
            exit
        } else {
            Start-Process $runningProcess -Verb RunAs
        }
    }
}

New-Alias -Name su -Value Enter-ElevatedPSSession

Set-Title