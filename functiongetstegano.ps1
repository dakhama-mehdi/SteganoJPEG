<#
.SYNOPSIS
    Analyzes image files (JPEG, PNG) to detect hidden files or data using steganographic techniques.

.DESCRIPTION
    This function scans the specified image files and identifies potential hidden files embedded
    within the images. It performs an in-depth analysis of the file structure to detect anomalies
    or embedded content that may have been inserted using steganography.

.PARAMETER filePath
    The full path to the image file to be analyzed. Supported formats include:
    - JPEG (*.jpg, *.jpeg)
    - PNG (*.png)

.EXAMPLE
    PS C:\> Get-HiddenFilesSpecificInImage -filePath "C:\Images\sample.jpg"
    This command analyzes the file `sample.jpg` and reports if any hidden files or data are detected.

.EXAMPLE
    PS C:\> gci C:\Images -Recurse -File -Include *.jpg,*.jpeg,*.png | ForEach-Object {
            Get-HiddenFilesSpecificInImage -filePath $_.FullName
        }
    This command recursively searches for image files in the `C:\Images` directory and analyzes each
    image for hidden content.

.NOTES
    Author: [Your Name]
    Date: [Date]
    Version: 1.0

    This function is part of the SteganoJPEG project, which aims to provide tools for detecting hidden
    files in images using advanced analysis techniques.

.LINK
    https://github.com/dakhama-mehdi/steganojpeg
#>

function Get-HiddenFilesSpecificInImage {
    param (
        [string]$filePath
    )

    $fileInfo = Get-Item $filePath
    $fileSizeMB = [math]::Round($fileInfo.Length / 1MB, 2)  

    # Skip file more than 4 Mo
    if ($fileSizeMB -gt 6) {
        $result = [PSCustomObject]@{
                    FilePath =  $filePath
                    pattern  = 'Large size'
                    Reason   = "File ignored: (size: $fileSizeMB MB)"
                }
        return $result
    }

    function Extractzip-fromfile {
    # Extract ZIP and list files inside it
                    $startIndex = $fileHex.IndexOf($magicNumber, $currentIndex) / 2  # Divide by 2 for hex chars
                    $zipBytes = $fileBytes[$startIndex..($fileBytes.Length - 1)]

                    $tempDir = [System.IO.Path]::GetTempPath()
                    $fileNameWithoutExtension = [System.IO.Path]::GetFileNameWithoutExtension($filePath)
                    $tempZipPath = [System.IO.Path]::Combine($tempDir, "$fileNameWithoutExtension.zip")
                    [System.IO.File]::WriteAllBytes($tempZipPath, $zipBytes)

                    # Read the ZIP file and list the files inside it
                    Add-Type -AssemblyName System.IO.Compression.FileSystem
                    $zip = [System.IO.Compression.ZipFile]::OpenRead($tempZipPath)
                    $fileNames = $zip.Entries | Select-Object -ExpandProperty FullName
                    $fileNames | ForEach-Object { Write-Host "File in ZIP: $_" }

                    $zip.Dispose()
                    Remove-Item $tempZipPath

                    $result = [PSCustomObject]@{
                        FilePath =  $filePath
                        Pattern  = 'Suspicious Image'
                        Reason   = "ZIP detected in pictures. Containing: $($fileNames -join ', ')"
                    }
                    return $result
    }

    try {
        # Read binary and convert file to Hex
        $fileBytes = [System.IO.File]::ReadAllBytes($filePath)
        $fileHex = [BitConverter]::ToString($fileBytes) -replace '-'
        $extension = [System.IO.Path]::GetExtension($filePath).TrimStart('.').ToLower()

        # Magic numbers for different file types
        $magicNumbers = [ordered]@{
            "MSI" = "D0CF11E0A1B11AE1" 
            "RAR" = "526172211A0700"  
            "ZIP" = "504B0304"
            "7z"  = "377ABCAF271C"
            "EXE" = "4D5A"
        }
       
        switch ($extension) {
        {$_ -in "jpg","jpeg"}  { $endoffile = "FFD9"}
        'png'   { $endoffile = "0000000049454E44AE426082"}
        'gif'   { $endoffile = "3B"}
        }

        foreach ($key in $magicNumbers.Keys) {
            $magicNumber = $magicNumbers[$key]
            $currentIndex = 0

            $truecheck = $endoffile + $magicNumber

        if (($fileHex -match $truecheck) -and ($fileHex.Substring($fileHex.Length -$endoffile.Length, $endoffile.Length) -ne $endoffile)) {

            if ($key -eq 'zip') { 
            return Extractzip-fromfile
            } else {
            $result = [PSCustomObject]@{
                                FilePath =  $filePath
                                pattern  = 'Suspicious Image'
                                Reason   = "$key file found in image with unexpected binary ending"
                            }
            return $result
            }
            }
            }
        
        foreach ($key in $magicNumbers.Keys) {
            $magicNumber = $magicNumbers[$key]
            $currentIndex = 0

            if ($fileHex -match $magicNumber) {
                if ($key -eq "EXE") {
                    while ($fileHex.IndexOf($magicNumber, $currentIndex) -ne -1) {
                        $startIndex = $fileHex.IndexOf($magicNumber, $currentIndex)
                        # Extract the part after the Magic Number (up to 200 bytes)
                        $remainingHex = $fileHex.Substring($startIndex + $magicNumber.Length, [Math]::Min(200 * 2, $fileHex.Length - ($startIndex + $magicNumber.Length)))

                        # Check if the string "0000004000" appears in the remaining data
             
                        if ($remainingHex -match "0000004000") {
                            $result = [PSCustomObject]@{
                                FilePath =  $filePath
                                pattern  = 'Suspicious Image'
                                Reason   = "EXE file with '0000004000' string detected"
                            }
                            return $result
                        }

                        # Continue searching from the next index
                        $currentIndex = $startIndex + $magicNumber.Length
                    }

                }
                elseif ($key -eq "ZIP") {
                return Extractzip-fromfile
                }
                else {
                    $result = [PSCustomObject]@{
                        FilePath =  $filePath
                        pattern  = 'Suspicious Image'
                        Reason   = "File $key detected in the image"
                    }
                    return $result
                }
            }
        }

        if ($fileHex.Substring($fileHex.Length -$endoffile.Length, $endoffile.Length) -ne $endoffile) {

       $Keywords = [ordered]@{
            "EXE file" = "4558452066696C65" 
            "printf"   = "7072696E7466"
        }

        # Search other motifs in the last 1000 characters
        $searchHex = $fileHex.Substring([Math]::Max(0, $fileHex.Length - 1000))
        foreach ($word in $Keywords.Keys) {
        if ($searchHex -match $Keywords[$word]) {
        
                  $result = [PSCustomObject]@{
                        FilePath =  $filePath
                        pattern  = 'Suspicious Image'
                        Reason   = "Image probably modified, with $word argument"
                    }
        return $result

        }
        }

        $result = [PSCustomObject]@{
                        FilePath =  $filePath
                        pattern  = 'Suspicious Image'
                        Reason   = "Image probably modified, not correctyl end binary match"
                    }
                    return $result
        }             
        


    }
    catch {
        $result = [PSCustomObject]@{
                 FilePath =  $filePath
                 pattern  = 'Error'
                 Reason   = "Details: $_"
                }
        return $result
    }
}

