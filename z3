handler.ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) =>
{
    // Se não houver erros de política SSL, o certificado é válido
    if (sslPolicyErrors == System.Net.Security.SslPolicyErrors.None)
        return true;

    // Carregar o CA-cert
    var caCert = new X509Certificate2(caCertPath);

    // Verificar se a cadeia contém o certificado da CA
    foreach (var element in chain.ChainElements)
    {
        if (element.Certificate.Thumbprint == caCert.Thumbprint)
        {
            return true; // Certificado confiável
        }
    }
