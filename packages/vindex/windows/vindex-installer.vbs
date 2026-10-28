' Vindex agent installer: install-code custom actions.
' Copyright (C) Viktrix Cyber Limited. GPLv2, as the Wazuh agent it ships with.
'
' An install code is created in the Vindex console (Endpoints > Add a device). It carries the
' tenant's enrolment settings so a customer only pastes one value. Format and fields are in
' packages/vindex/docs/install-code.md:
'     VDX1.<base64url(UTF-8 query string)>   e.g. m=agents.example.com&g=tenant_acme&x=1767225600
'
' Explicit VINDEX_* properties always win; the code only fills properties that are empty.

Option Explicit

Const ERROR_SUCCESS = 1
Const ERROR_INSTALL_FAILURE = 3

' Pure VBScript (no COM objects): the payload is a percent-encoded ASCII query string.
Private Function Base64UrlDecode(ByVal s)
    Const ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    Dim i, c, v, bits, nbits, b, out
    s = Replace(Replace(s, "+", "-"), "/", "_")
    Do While Right(s, 1) = "="
        s = Left(s, Len(s) - 1)
    Loop
    If Len(s) = 0 Or Len(s) Mod 4 = 1 Then Err.Raise vbObjectError + 1, , "bad length"
    bits = 0
    nbits = 0
    out = ""
    For i = 1 To Len(s)
        c = Mid(s, i, 1)
        v = InStr(1, ALPHA, c, vbBinaryCompare) - 1
        If v < 0 Then Err.Raise vbObjectError + 2, , "bad character"
        bits = bits * 64 + v
        nbits = nbits + 6
        If nbits >= 8 Then
            nbits = nbits - 8
            b = Int(bits / (2 ^ nbits))
            bits = bits - b * (2 ^ nbits)
            If b < 32 Or b > 126 Then Err.Raise vbObjectError + 3, , "not ASCII"
            out = out & Chr(b)
        End If
    Next
    Base64UrlDecode = out
End Function

' Percent-decoding limited to printable ASCII, matching the install-code contract.
Private Function PercentDecode(ByVal s)
    Dim i, c, b, out
    out = ""
    i = 1
    Do While i <= Len(s)
        c = Mid(s, i, 1)
        If c = "%" Then
            If i + 2 > Len(s) Then Err.Raise vbObjectError + 4, , "bad escape"
            b = CLng("&H" & Mid(s, i + 1, 2))
            If b < 32 Or b > 126 Then Err.Raise vbObjectError + 5, , "not printable ASCII"
            out = out & Chr(b)
            i = i + 3
        ElseIf c = "+" Then
            out = out & " "
            i = i + 1
        Else
            out = out & c
            i = i + 1
        End If
    Loop
    PercentDecode = out
End Function

' Seconds since 1970-01-01 UTC, or -1 when the clock cannot be read.
Private Function UnixNowUtc()
    Dim wmi, item, bias
    UnixNowUtc = -1
    On Error Resume Next
    Set wmi = GetObject("winmgmts:\\.\root\cimv2")
    For Each item In wmi.ExecQuery("SELECT * FROM Win32_UTCTime")
        UnixNowUtc = DateDiff("s", DateSerial(1970, 1, 1), DateSerial(item.Year, item.Month, item.Day) + _
            TimeSerial(item.Hour, item.Minute, item.Second))
    Next
    If UnixNowUtc < 0 Then
        Err.Clear
        ' Local time + ActiveTimeBias (minutes) = UTC.
        bias = CreateObject("WScript.Shell").RegRead( _
            "HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation\ActiveTimeBias")
        If Err.Number = 0 Then UnixNowUtc = DateDiff("s", DateSerial(1970, 1, 1), Now) + CLng(bias) * 60
    End If
    Err.Clear
    On Error GoTo 0
End Function

' Values must be plain host names, group names or numbers: they are written into ossec.conf.
Private Function SafeValue(ByVal key, ByVal v)
    Dim re
    Set re = New RegExp
    Select Case key
        Case "p", "rp", "x"
            re.Pattern = "^[0-9]{1,10}$"
        Case "m", "r"
            re.Pattern = "^[A-Za-z0-9.:\-\[\],]{1,512}$"
        Case "g"
            re.Pattern = "^[A-Za-z0-9_.\-,]{1,255}$"
        Case "k"
            re.Pattern = "^[ !#-%'-;=?-~]{1,128}$" ' printable ASCII except " & < >
        Case Else
            SafeValue = True
            Exit Function
    End Select
    SafeValue = re.Test(v)
End Function

Private Sub LogInfo(ByVal msg)
    Dim rec
    Set rec = Session.Installer.CreateRecord(0)
    rec.StringData(0) = "Vindex: " & msg
    Session.Message &H04000000, rec ' INSTALLMESSAGE_INFO
End Sub

Private Sub SetIfEmpty(ByVal prop, ByVal v)
    If Session.Property(prop) = "" And v <> "" Then Session.Property(prop) = v
End Sub

' Immediate custom action (UI and execute sequences). Sets VINDEX_CODE_VALID to "1" or "0" and
' VINDEX_CODE_ERROR to a message the dialog can show. Fails the install only in the execute
' sequence, so a typo in the dialog returns the user to the field instead of aborting.
Function DecodeInstallCode()
    Dim code, payload, pairs, pair, i, kv, key, val, fields, failInstall
    DecodeInstallCode = ERROR_SUCCESS
    failInstall = (Session.Property("VINDEX_IN_EXECUTE") = "1")
    Session.Property("VINDEX_CODE_VALID") = "0"
    code = Trim(Session.Property("INSTALL_CODE"))
    If code = "" Then
        Session.Property("VINDEX_CODE_ERROR") = "Enter the install code from the Vindex console."
        Exit Function
    End If
    If Left(code, 5) <> "VDX1." Then
        Session.Property("VINDEX_CODE_ERROR") = "This is not a Vindex install code. Copy it again from the console."
        LogInfo Session.Property("VINDEX_CODE_ERROR")
        If failInstall Then DecodeInstallCode = ERROR_INSTALL_FAILURE
        Exit Function
    End If

    On Error Resume Next
    payload = Base64UrlDecode(Mid(code, 6))
    If Err.Number <> 0 Then
        Err.Clear
        On Error GoTo 0
        Session.Property("VINDEX_CODE_ERROR") = "The install code is damaged. Copy it again from the console."
        LogInfo Session.Property("VINDEX_CODE_ERROR")
        If failInstall Then DecodeInstallCode = ERROR_INSTALL_FAILURE
        Exit Function
    End If
    On Error GoTo 0

    Set fields = CreateObject("Scripting.Dictionary")
    pairs = Split(payload, "&")
    For i = 0 To UBound(pairs)
        pair = pairs(i)
        kv = InStr(pair, "=")
        If kv > 1 Then
            key = Left(pair, kv - 1)
            On Error Resume Next
            val = PercentDecode(Mid(pair, kv + 1))
            If Err.Number <> 0 Then val = Chr(0)
            Err.Clear
            On Error GoTo 0
            If Not SafeValue(key, val) Then
                Session.Property("VINDEX_CODE_ERROR") = "The install code contains an invalid value. Create a new code."
                LogInfo Session.Property("VINDEX_CODE_ERROR")
        If failInstall Then DecodeInstallCode = ERROR_INSTALL_FAILURE
                Exit Function
            End If
            fields(key) = val
        End If
    Next

    If Not fields.Exists("m") Or Not fields.Exists("g") Then
        Session.Property("VINDEX_CODE_ERROR") = "The install code is incomplete. Create a new code."
        LogInfo Session.Property("VINDEX_CODE_ERROR")
        If failInstall Then DecodeInstallCode = ERROR_INSTALL_FAILURE
        Exit Function
    End If
    If fields.Exists("x") Then
        Dim nowUtc
        nowUtc = UnixNowUtc()
        If nowUtc < 0 Then
            Session.Property("VINDEX_CODE_ERROR") = "The device clock could not be read to check the install code."
            LogInfo Session.Property("VINDEX_CODE_ERROR")
            If failInstall Then DecodeInstallCode = ERROR_INSTALL_FAILURE
            Exit Function
        End If
        If CDbl(fields("x")) < CDbl(nowUtc) Then
            Session.Property("VINDEX_CODE_ERROR") = "This install code has expired. Create a new one in the console."
            LogInfo Session.Property("VINDEX_CODE_ERROR")
        If failInstall Then DecodeInstallCode = ERROR_INSTALL_FAILURE
            Exit Function
        End If
    End If

    SetIfEmpty "VINDEX_MANAGER", fields("m")
    SetIfEmpty "VINDEX_AGENT_GROUP", fields("g")
    If fields.Exists("r") Then SetIfEmpty "VINDEX_REGISTRATION_SERVER", fields("r") Else SetIfEmpty "VINDEX_REGISTRATION_SERVER", fields("m")
    If fields.Exists("p") Then SetIfEmpty "VINDEX_MANAGER_PORT", fields("p")
    If fields.Exists("rp") Then SetIfEmpty "VINDEX_REGISTRATION_PORT", fields("rp")
    If fields.Exists("k") Then SetIfEmpty "VINDEX_REGISTRATION_PASSWORD", fields("k")
    Session.Property("VINDEX_CODE_VALID") = "1"
    Session.Property("VINDEX_CODE_ERROR") = ""
End Function
