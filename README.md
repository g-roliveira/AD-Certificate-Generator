# Script para gerar certificados para usuários do Active Directory

## Principais funções de cada bloco.

### Função `Get-NewCert`

Esta é a função que recebe um parâmetro `requser` e gera um certificado para o usuário especificado. Ele usa a biblioteca .NET `X509Enrollment` para criar uma solicitação de certificado, solicitar um certificado usando a solicitação e gravar o certificado em um arquivo PFX.

```powershell
function Get-NewCert {
    param (
        [Parameter()]
        [string] $requser
    )

    $PKCS10 = New-Object -ComObject X509Enrollment.CX509CertificateRequestPkcs10
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
```
## Definindo as variáveis
As variáveis de configuração do script são definidas no início do script. O nome do domínio, o nome do modelo de certificado, o Thumbprint do certificado do usuário e o caminho onde os certificados serão salvos são definidos aqui.

Define o nome do seu domínio, split do sufixo, template e ThumbPrit do Certificado a ser usado.
```powershell
$DomainName = "contoso.com"
$DomainSuffixSplit = $DomainName.Split(".")[0]
$TemplateName = "contosoUser"
$UserCertThumbPrint = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
```
Define o caminho para salvar os certificados e senha
```powershell
$CertPath = "C:\temp\certs\"
```

## Solicitando o nome do usuário
O script solicita o nome do usuário para o qual um certificado será gerado. Se o usuário não for encontrado, o script solicita ao usuário se ele deseja tentar novamente ou sair.
```powershell
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
```

## Verificando se o usuário já tem um certificado válido
Se o usuário já tiver um certificado válido, o script pergunta ao usuário se ele deseja renovar o certificado ou exportar o certificado existente. O script também verifica se o certificado existente está prestes a expirar. Se o usuário escolher exportar o certificado existente, o script exportará o certificado para um arquivo PFX e salvará a senha em um arquivo de texto.

```powershell
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
```

## Princiais comandos e variáveis

- `Get-NewCert`: função que gera um novo certificado com base nos parâmetros informados.
- `$DomainName`: nome do domínio do Active Directory.
- `$DomainSuffixSplit`: prefixo do nome do domínio.
- `$TemplateName`: nome do template de certificado.
- `$UserCertThumbPrint`: impressão digital do certificado do usuário atual.
- `$UserCert`: objeto que contém as informações do certificado do usuário.
- `$UserCertSubject`: assunto do certificado do usuário atual.
- `$CertPath`: caminho para salvar os certificados gerados.
- `$UserName`: nome do usuário informado pelo usuário.
- `Get-ADUser`: cmdlet do PowerShell que retorna um objeto de usuário do Active Directory com base no filtro fornecido.
- `$User`: objeto de usuário do Active Directory correspondente ao nome de usuário fornecido.
- `$requser`: nome de usuário SAMAccountName.
- `$subject`: assunto do certificado.
- `$attcert`: caminho para salvar o arquivo de certificado.
- `$PassFileName`: caminho para salvar o arquivo de senha do certificado.
- `Get-ChildItem`: cmdlet do PowerShell que retorna uma lista de itens em um determinado caminho.
- `Export-PfxCertificate`: cmdlet do PowerShell que exporta um certificado para um arquivo PFX.
- `$resp`: resposta do usuário à pergunta se deseja renovar ou exportar um certificado existente.
- `Write-Host`: cmdlet do PowerShell que exibe mensagens na tela.
- `$passwd`: senha gerada aleatoriamente para proteger o arquivo PFX do certificado.
- `Out-File`: cmdlet do PowerShell que salva uma saída em um arquivo.
- `try`, `catch`: bloco de tratamento de erros do PowerShell.
- `$PKCS10`: objeto PKCS10 usado para solicitar um certificado.
- `$PKCS10.InitializeFromTemplateName()`: método usado para inicializar o objeto PKCS10 com o nome do template de certificado.
- `$PKCS10.Encode()`: método usado para codificar o objeto PKCS10.
- `$pkcs7`: objeto PKCS7 usado para encapsular a solicitação de certificado.
- `$pkcs7.InitializeFromInnerRequest()`: método usado para inicializar o objeto PKCS7 com a solicitação de certificado encapsulada.
- `$pkcs7.RequesterName`: nome do solicitante do certificado.
- `$signer`: objeto que representa o certificado do assinante.
- `$signer.Initialize()`: método usado para inicializar o objeto CSignerCertificate com o certificado do assinante.
- `$Request`: objeto CX509Enrollment usado para solicitar o certificado.
- `$Request.InitializeFromRequest()`: método usado para inicializar o objeto CX509Enrollment com a solicitação de certificado.
- `$Request.Enroll()`: método usado para enviar a solicitação de certificado para a autoridade de certificação.
- `param`: palavra-chave usada para definir os parâmetros de entrada da função Get-NewCert.
- `[Parameter()]`: atributo usado para definir as propriedades do parâmetro `$requser`.
- `Write-Error`: cmdlet do PowerShell usado para exibir uma mensagem de erro e encerrar a execução do script.
- `Test-Path -Path $CertPath -PathType Container`: cmdlet do PowerShell usado para verificar se o caminho especificado é um diretório válido.
- `New-Item -ItemType Directory -Path $CertPath`: cmdlet do PowerShell usado para criar um diretório no caminho especificado.
- `Read-Host`: cmdlet do PowerShell usado para solicitar entrada do usuário.
- `Filter`: parâmetro usado para filtrar a pesquisa de usuários.
- `{ SamAccountName -eq $UserName }`: propriedade e valor usados para filtrar a pesquisa de usuários pelo nome de usuário.
- `-Properties SamAccountName,DistinguishedName`: parâmetro usado para especificar quais propriedades de usuário recuperar.
- `-Server $DomainName`: parâmetro usado para especificar qual controlador de domínio do Active Directory realizar a pesquisa de usuários.
- `$User`: objeto que contém as informações do usuário pesquisado.
- `$User.SamAccountName`: propriedade que contém o nome de usuário do usuário pesquisado.
- `$User.distinguishedName`: propriedade que contém o nome distintivo do usuário pesquisado.
- `$subject`: nome distintivo do usuário pesquisado formatado para salvar no arquivo PFX do certificado.
- `$UserName + ".pfx"`: nome do arquivo PFX do certificado a ser gerado.
- `if ((Get-ChildItem -Path "Cert:\CurrentUser\My" -DnsName $requser -ErrorAction SilentlyContinue) -and (Get-ChildItem -Path "Cert:\CurrentUser\My" -DnsName $requser).NotAfter -gt (Get-Date).AddDays(30))`: condição usada para verificar se o usuário já possui um certificado válido que não está prestes a expirar.
- `Get-Date`: cmdlet do PowerShell que retorna a data e hora atuais.
- `Renovar / Exportar`: opções oferecidas ao usuário para renovar ou exportar o certificado existente.
- `Exit`: cmdlet do PowerShell que finaliza a execução do script.

*Obs: Este é o script para gerar certificados para usuários do Active Directory. Certifique-se de modificar as variáveis de configuração no início do script de acordo com sua configuração e use-o com cuidado.*
