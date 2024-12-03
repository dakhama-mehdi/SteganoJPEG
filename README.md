# SteganoJPEG

**SteganoJPEG** is a detection and analysis tool designed to identify hidden files within JPEG images. It leverages steganalysis techniques and incorporates parts of the [Hardensysvole](https://github.com/your-hardensysvole-link-if-available) project. This tool is ideal for security researchers, digital forensics experts, or anyone curious about uncovering secrets hidden in images.

## Features

<ul>
  <li><strong>Metadata and JPEG Structure Analysis</strong>: Deep inspection of headers and segments to detect anomalies or suspicious data.</li>
  <li><strong>Hidden File Detection</strong>: Extract and identify embedded data using steganographic techniques.</li>
  <li><strong>Hardensysvole Integration</strong>: Optimized integration of search and analysis algorithms from the Hardensysvole project.</li>
  <li><strong>User-Friendly Interface</strong>: Simple command-line execution for quick usage.</li>
</ul>

## Installation

<ol>
  <li>Copy function on your ISE and run it
  </li>
</ol>

## Usage

<p>To use the tool, simply copy the function or PowerShell script into an ISE and call it as follows:</p>

<pre><code>
gci C:\path -Recurse -File -Include *.jpg,*.jpeg,*.png | ForEach-Object {

    Get-HiddenFilesSpecificInImage -filePath $_.fullname

}
</code></pre>

<p>The program will analyze the images and indicate if hidden files are detected, along with their type and extracted content (if possible).</p>

## Example Output

<table>
  <thead>
    <tr>
      <th>Image Path</th>
      <th>Hidden File Detected</th>
      <th>File Type</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>C:\path\image1.jpg</td>
      <td>Yes</td>
      <td>ZIP Archive</td>
    </tr>
    <tr>
      <td>C:\path\image2.png</td>
      <td>No</td>
      <td>N/A</td>
    </tr>
  </tbody>
</table>

## Contributions

<p>Contributions are welcome to improve algorithms, add features, or optimize performance. Please submit your proposals via pull requests.</p>
