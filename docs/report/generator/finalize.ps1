# Requires Microsoft Word: populates the table of contents, saves the final .docx and .pdf
# one level up (docs/report), and renders PDF pages to generator/pages for visual checks.
$dir = $PSScriptRoot
$report = (Resolve-Path (Join-Path $dir "..")).Path
$word = New-Object -ComObject Word.Application
$word.Visible = $false; $word.DisplayAlerts = 0
try {
  $doc = $word.Documents.Open("$dir\raw_report.docx", $false, $false)
  foreach ($toc in $doc.TablesOfContents) { $toc.Update() }
  $doc.Repaginate()
  "pages: $($doc.ComputeStatistics(2)) words: $($doc.ComputeStatistics(0)) tables: $($doc.Tables.Count)"
  $doc.SaveAs2("$report\AegisWeave_Project_Report.docx", 16)
  $doc.SaveAs2("$report\AegisWeave_Project_Report.pdf", 17)
  $doc.Close($false)
} finally { $word.Quit() | Out-Null }
$pages = Join-Path $dir "pages"; Remove-Item "$pages\*.png" -ErrorAction SilentlyContinue; New-Item -ItemType Directory -Force $pages | Out-Null
Add-Type -AssemblyName System.Runtime.WindowsRuntime
$null = [Windows.Storage.StorageFile, Windows.Storage, ContentType = WindowsRuntime]
$null = [Windows.Storage.StorageFolder, Windows.Storage, ContentType = WindowsRuntime]
$null = [Windows.Data.Pdf.PdfDocument, Windows.Data.Pdf, ContentType = WindowsRuntime]
$null = [Windows.Data.Pdf.PdfPageRenderOptions, Windows.Data.Pdf, ContentType = WindowsRuntime]
$methods = [System.WindowsRuntimeSystemExtensions].GetMethods()
$asTask = ($methods | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
$asAction = ($methods | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncAction' })[0]
function Await($op, [Type]$type) { $t = $asTask.MakeGenericMethod($type).Invoke($null, @($op)); $t.Wait(-1) | Out-Null; $t.Result }
function AwaitAction($op) { $t = $asAction.Invoke($null, @($op)); $t.Wait(-1) | Out-Null }
$file = Await ([Windows.Storage.StorageFile]::GetFileFromPathAsync("$report\AegisWeave_Project_Report.pdf")) ([Windows.Storage.StorageFile])
$pdf = Await ([Windows.Data.Pdf.PdfDocument]::LoadFromFileAsync($file)) ([Windows.Data.Pdf.PdfDocument])
$folder = Await ([Windows.Storage.StorageFolder]::GetFolderFromPathAsync($pages)) ([Windows.Storage.StorageFolder])
for ($i = 0; $i -lt $pdf.PageCount; $i++) {
  $page = $pdf.GetPage($i)
  $out = Await ($folder.CreateFileAsync(("page-{0:D2}.png" -f ($i + 1)), [Windows.Storage.CreationCollisionOption]::ReplaceExisting)) ([Windows.Storage.StorageFile])
  $stream = Await ($out.OpenAsync([Windows.Storage.FileAccessMode]::ReadWrite)) ([Windows.Storage.Streams.IRandomAccessStream])
  $opts = New-Object Windows.Data.Pdf.PdfPageRenderOptions; $opts.DestinationWidth = 850
  AwaitAction ($page.RenderToStreamAsync($stream, $opts)); $stream.Dispose(); $page.Dispose()
}
"rendered $($pdf.PageCount) pages"
