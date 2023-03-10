# Função que recebe parametro e gera certificado.
function Get-NewCert {
    param (
        [Parameter()]
        [string] $requser
    )

    $PKCS10 = New-Object -ComObject X509Enrollment.CX509CertificateRequestPkcs10
    # Object identifier do Certificate template
    $PKCS10.InitializeFromTemplateName(0x1, $TemplateName)
    $PKCS10.Encode()
    $pkcs7 = New-Object -ComObject X509enrollment.CX509CertificateRequestPkcs7
    $pkcs7.InitializeFromInnerRequest($pkcs10)
    $pkcs7.RequesterName = $DomainSuffixSplit + "\" + $requser
    $signer = New-Object -ComObject X509Enrollment.CSignerCertificate
    $signer.Initialize(0, 0, 0xc, $UserCertThumbPrint)
    $pkcs7.SignerCertificate = $signer
    $Request = New-Object -ComObject X509Enrollment.CX509Enrollment
    $Request.InitializeFromRequest($pkcs7)
    try {
        $Request.Enroll()
    }
    catch {
        Write-Host "Erro ao gerar o certificado. Verifique se o usuário $UserCertSubject possui permissão para gerar certificados com o template "$TemplateName" e se o certificado está instalado na máquina."
        exit
    }
}

# Define o nome do seu domínio
$DomainName = "contoso.local"
$DomainSuffixSplit = $DomainName.Split(".")[0]
$TemplateName = "Contoso_User"
$UserCertThumbPrint = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
$UserCert = Get-ChildItem -Path Cert:\CurrentUser\My | Where-Object { $_.Thumbprint -eq $UserCertThumbPrint }
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

# Obtém todos os usuários do grupo GG_RUNDECK_ADMIN
$GroupName = "GG_CONTOSO_USERS"
$GroupMembers = Get-ADGroupMember -Identity $GroupName

# Loop Foreach para iterar por cada usuário do grupo
foreach ($Member in $GroupMembers) {
    $User = Get-ADUser -Identity $Member.distinguishedName -Properties SamAccountName, DistinguishedName -Server $DomainName

    if ($User -eq $null) {
        Write-Host "Usuário não encontrado no AD."
    }
    else {
        $requser = $User.SamAccountName.ToString()
        $subject = $User.distinguishedName.Replace(",", ", ")
        $passwd = ("!@0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".tochararray() | Sort-Object { Get-Random })[0..6] -join ''
        $attcert = $CertPath + $requser + ".pfx"
        $PassFileName = $CertPath + $requser + "-pass.txt"

        # Verifica se o usuário já possui um certificado emitido ou se o certificado existente está prestes a expirar
        $Cert = Get-ChildItem -Path "Cert:\CurrentUser\My" -DnsName $requser -ErrorAction SilentlyContinue | ? {$_.Extensions | ? {$_.oid.friendlyname -match "Template" -and $_.Format(0) -match $TemplateName}}
        if ($Cert -ne $null -and $Cert.NotAfter -gt (Get-Date).AddDays(90)) {
            Get-ChildItem -Path cert:\CurrentUser\my | Where-Object -Property Subject -eq $subject | Export-PfxCertificate -NoProperties -FilePath $attcert -Password (ConvertTo-SecureString -String $passwd -Force -AsPlainText)
			$passwd | Out-File $PassFileName
            Write-Host "Usuário já possui um certificado válido que não está prestes a expirar. Certificado e senha exportado!"
            Write-Host "O certificado foi salvo em $attcert."
            Write-Host "A senha foi salva em $PassFileName."
            
            # Renova o certificado se a opção for especificada
            if ($RenovarCertificado) {
                Get-NewCert -requser $requser        
                Get-ChildItem -Path cert:\CurrentUser\my | Where-Object -Property Subject -eq $subject | Export-PfxCertificate -NoProperties -FilePath $attcert -Password (ConvertTo-SecureString -String $passwd -Force -AsPlainText)
				# Grava a senha gerada no arquivo de texto
				$passwd | Out-File $PassFileName
                Write-Host "Novo certificado gerado com sucesso."
                Write-Host "O certificado foi salvo em $attcert."
                Write-Host "A senha foi salva em $PassFileName."
            }
        }
        else {
            # Gera um novo certificado
            Get-NewCert -requser $requser        
            Get-ChildItem -Path cert:\CurrentUser\my | Where-Object -Property Subject -eq $subject | Export-PfxCertificate -NoProperties -FilePath $attcert -Password (ConvertTo-SecureString -String $passwd -Force -AsPlainText)
            # Grava a senha gerada no arquivo de texto
            $passwd | Out-File $PassFileName
			Write-Host "Certificado gerado com sucesso."
            Write-Host "O certificado foi salvo em $attcert."
            Write-Host "A senha foi salva em $PassFileName."
        }
    }
}