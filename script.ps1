# Função que recebe parametro e gera certificado.
function Get-NewCert {
    param (
        [Parameter()]
        [string] $requser
    )

    $PKCS10 = New-Object -ComObject X509Enrollment.CX509CertificateRequestPkcs10
    # Object identifier do Certificate template
    $PKCS10.InitializeFromTemplateName(0x1,$TemplateName)
    $PKCS10.Encode()
    $pkcs7 = New-Object -ComObject X509enrollment.CX509CertificateRequestPkcs7
    $pkcs7.InitializeFromInnerRequest($pkcs10)
    $pkcs7.RequesterName = $DomainSuffixSplit+"\"+$requser
    $signer = New-Object -ComObject X509Enrollment.CSignerCertificate
    $signer.Initialize(0,0,0xc,$UserCertThumbPrint)
    $pkcs7.SignerCertificate = $signer
    $Request = New-Object -ComObject X509Enrollment.CX509Enrollment
    $Request.InitializeFromRequest($pkcs7)
    $Request.Enroll()
    try {
        $Request.Enroll()
    } catch {
        Write-Host "Erro ao gerar o certificado. Verifique se o usuário $UserCertSubject possui permissão para gerar certificados com o template "$TemplateName" e se o certificado está instalado na máquina."
        exit
    }
}

# Define o nome do seu domínio
$DomainName = "contoso.com"
$DomainSuffixSplit = $DomainName.Split(".")[0]
$TemplateName = "contosoUser"
$UserCertThumbPrint = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
$UserCert = Get-ChildItem -Path Cert:\CurrentUser\My | Where-Object {$_.Thumbprint -eq $UserCertThumbPrint}
if ($UserCert -eq $null) {
    Write-Error "O certificado com Thumbprint $UserCertThumbPrint não foi encontrado."
    Exit
}
$UserCertSubject = $UserCert.Subject.Split(",")[0]

# Define o caminho para salvar os certificados
$CertPath = "C:\temp\certs\"
if (-not (Test-Path -Path $CertPath -PathType Container)) {
    Write-Host "Diretório $CertPath não existe. Criando diretório."
    New-Item -ItemType Directory -Path $CertPath
}

# Solicita o nome do usuário
do {
    $UserName = Read-Host "Digite o nome do usuário para gerar o Certificado"

    # Realiza a pesquisa do usuário no Active Directory
    $User = Get-ADUser -Filter { SamAccountName -eq $UserName } -Properties SamAccountName,DistinguishedName -Server $DomainName

    if ($User -eq $null) {
        Write-Host "Usuário $UserName não encontrado no AD. Deseja digitar outro usuário? (S/N)"
        $opcao = Read-Host
        if ($opcao -eq "N") {
            exit
        }
    }
} while ($User -eq $null)

$requser = $User.SamAccountName.ToString()
$subject = $User.distinguishedName.Replace(",",", ")
$passwd = ("!@0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".tochararray() | Sort-Object {Get-Random})[0..6] -join ''
$attcert = $CertPath + $UserName + ".pfx"
$PassFileName = $CertPath + $UserName + "-pass.txt"


# Verifica se o usuário já possui um certificado emitido ou se o certificado existente está prestes a expirar
if ((Get-ChildItem -Path "Cert:\CurrentUser\My" -DnsName $requser -ErrorAction SilentlyContinue) -and (Get-ChildItem -Path "Cert:\CurrentUser\My" -DnsName $requser).NotAfter -gt (Get-Date).AddDays(30)) {
    $resp = Read-Host "Usuário já possui um certificado válido que não está prestes a expirar. `nDeseja renovar o certificado ou exportar o certificado já existente? `n(R - Renovar / E - Exportar)(Default = Exportar)"
    if ($resp -eq "R" -or $resp -eq "r") {
        Get-NewCert -requser $requser        
        Get-ChildItem -Path cert:\CurrentUser\my | Where-Object -Property Subject -eq $subject | Export-PfxCertificate -NoProperties -FilePath $attcert -Password (ConvertTo-SecureString -String $passwd -Force -AsPlainText)
        Write-Host "Certificado gerado com sucesso."
        Write-Host "O certificado foi salvo em $attcert."
        Write-Host "A senha foi salva em $PassFileName."
    
        # Grava a senha gerada no arquivo de texto
        $passwd | Out-File $PassFileName

    } elseif ($resp -eq "E" -or $resp -eq "e" -or $resp -eq "" ) {
        Get-ChildItem -Path cert:\CurrentUser\my | Where-Object -Property Subject -eq $subject | Export-PfxCertificate -NoProperties -FilePath $attcert -Password (ConvertTo-SecureString -String $passwd -Force -AsPlainText)
        $passwd | Out-File $PassFileName
        Write-Host "Certificado exportado com sucesso."
        Write-Host "A senha foi salva em $PassFileName."
    } else {
        Write-Host "Opção inválida."
    }
} else {
    Get-NewCert -requser $requser        
    Get-ChildItem -Path cert:\CurrentUser\my | Where-Object -Property Subject -eq $subject | Export-PfxCertificate -NoProperties -FilePath $attcert -Password (ConvertTo-SecureString -String $passwd -Force -AsPlainText)
    Write-Host "Certificado gerado com sucesso."
    Write-Host "O certificado foi salvo em $attcert."
    Write-Host "A senha foi salva em $PassFileName."

    # Grava a senha gerada no arquivo de texto
    $passwd | Out-File $PassFileName
}
