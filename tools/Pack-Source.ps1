#requires -Version 7.0
param([string]$Destination=(Join-Path $PSScriptRoot '../../远程控制-开源签名候选版-20260930.zip'))
$ErrorActionPreference='Stop'
$repoRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
& (Join-Path $PSScriptRoot 'Audit-PublicSource.ps1') -Root $repoRoot
$target=[IO.Path]::GetFullPath($Destination)
if(Test-Path -LiteralPath $target){throw '源码包已存在；禁止覆盖'}
$files=Get-ChildItem -LiteralPath $repoRoot -Recurse -File | Where-Object {$_.FullName -notmatch '[\\/](\.git|artifacts|\.tools)[\\/]'}
$stream=[IO.File]::Open($target,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
$archive=[IO.Compression.ZipArchive]::new($stream,[IO.Compression.ZipArchiveMode]::Create,$false,[Text.UTF8Encoding]::new($false))
try{
 foreach($file in ($files|Sort-Object FullName)){
  if($file.Attributes -band [IO.FileAttributes]::ReparsePoint){throw '拒绝打包符号链接或重解析点'}
  $rel=[IO.Path]::GetRelativePath($repoRoot,$file.FullName).Replace('\','/')
  $entry=$archive.CreateEntry('vsme-remote-control/'+$rel,[IO.Compression.CompressionLevel]::Optimal)
  $output=$entry.Open();$input=[IO.File]::OpenRead($file.FullName)
  try{$input.CopyTo($output)}finally{$input.Dispose();$output.Dispose()}
 }
}finally{$archive.Dispose();$stream.Dispose()}
Get-FileHash -LiteralPath $target -Algorithm SHA256
