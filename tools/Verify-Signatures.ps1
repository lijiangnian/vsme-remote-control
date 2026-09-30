#requires -Version 7.0
param([string]$Root=(Join-Path $PSScriptRoot '../artifacts'),[switch]$CoresOnly,[string]$ExpectedSignerThumbprint='')
$ErrorActionPreference='Stop'
function Assert-TrustedRSA([string]$Path){
 $signature=Get-AuthenticodeSignature -LiteralPath $Path
 if($signature.Status -ne 'Valid'){throw "签名未通过系统信任校验：$([IO.Path]::GetFileName($Path)) / $($signature.Status)"}
 if($signature.SignerCertificate.PublicKey.Oid.Value -ne '1.2.840.113549.1.1.1'){throw '智能应用控制发布门禁要求 RSA Authenticode 证书'}
 if($null -eq $signature.TimeStamperCertificate){throw '发布签名缺少可信时间戳'}
 if($ExpectedSignerThumbprint -and $signature.SignerCertificate.Thumbprint -ne $ExpectedSignerThumbprint.Replace(' ','')){throw '签名者与指定证书不一致'}
 [pscustomobject]@{File=[IO.Path]::GetFileName($Path);Status='Valid';Signer=$signature.SignerCertificate.Subject;Thumbprint=$signature.SignerCertificate.Thumbprint;SHA256=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash}
}
$rootPath=[IO.Path]::GetFullPath($Root)
$coreRoot=if($CoresOnly){$rootPath}else{Join-Path $rootPath 'Core'}
$verified=@()
foreach($role in @('Control','Agent')){$verified+=Assert-TrustedRSA (Join-Path $coreRoot "$role-core.exe")}
if(-not $CoresOnly){
 foreach($role in @('Control','Agent')){
  $name=if($role -eq 'Control'){'远程控制-主控端.exe'}else{'远程控制-被控端.exe'}
  $wrapper=Join-Path $rootPath "Windows/$name"
  $outer=Assert-TrustedRSA $wrapper
  $assembly=[Reflection.Assembly]::Load([IO.File]::ReadAllBytes($wrapper))
  $stream=$assembly.GetManifestResourceStream('Core.exe')
  if($null -eq $stream){throw '外壳没有内部引擎资源'}
  $temp=New-TemporaryFile
  try{
   $output=[IO.File]::OpenWrite($temp.FullName)
   try{$stream.CopyTo($output)}finally{$output.Dispose();$stream.Dispose()}
   $embedded=Assert-TrustedRSA $temp.FullName
   $original=Join-Path $coreRoot "$role-core.exe"
   if($embedded.SHA256 -ne (Get-FileHash -LiteralPath $original -Algorithm SHA256).Hash){throw '外壳嵌入的引擎不是已校验的签名引擎'}
   if($embedded.Thumbprint -ne $outer.Thumbprint){throw '外壳与引擎签名者不一致'}
   if($assembly.GetName().Version.ToString() -ne (Get-Item -LiteralPath $original).VersionInfo.ProductVersion){throw '外壳与引擎版本不一致'}
  }finally{Remove-Item -LiteralPath $temp.FullName -Force}
  $verified+=$outer
 }
}
$verified
