#requires -Version 7.0
param(
 [ValidateSet('Cores','Wrappers')][string]$Stage='Cores',
 [ValidatePattern('^\d+\.\d+\.\d+\.\d+$')][string]$Version='2.1.2.0',
 [string]$Go='go',
 [switch]$UnsignedDevelopmentOnly
)
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$repoRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$artifactRoot=Join-Path $repoRoot 'artifacts'
foreach($part in @('Core','Windows','Mac','metadata')){[IO.Directory]::CreateDirectory((Join-Path $artifactRoot $part))|Out-Null}
$candidateCompiler=Join-Path $env:WINDIR 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
if($Stage -eq 'Wrappers'){
 if(-not $UnsignedDevelopmentOnly){& (Join-Path $PSScriptRoot 'Verify-Signatures.ps1') -Root (Join-Path $artifactRoot 'Core') -CoresOnly}
 $versionSource=Join-Path $artifactRoot 'metadata/Version.cs'
 [IO.File]::WriteAllText($versionSource,"using System.Reflection;`n[assembly: AssemblyVersion(`"$Version`")]`n[assembly: AssemblyFileVersion(`"$Version`")]`n[assembly: AssemblyInformationalVersion(`"$Version`")]`n",[Text.UTF8Encoding]::new($false))
 foreach($role in @('Control','Agent')){
  $core=Join-Path $artifactRoot ("Core/$role-core.exe")
  if(-not(Test-Path -LiteralPath $core)){throw "缺少内部引擎：$role"}
  $coreInfo=(Get-Item -LiteralPath $core).VersionInfo
  if($coreInfo.ProductVersion -ne $Version -or $coreInfo.ProductName -ne 'VSME Remote Control'){throw '内部引擎产品名或版本不匹配'}
  $fileName=if($role -eq 'Control'){'远程控制-主控端.exe'}else{'远程控制-被控端.exe'}
  $buildArgs=@('/nologo','/target:winexe','/platform:x64','/optimize+','/reference:System.Drawing.dll','/reference:System.Windows.Forms.dll','/reference:System.Web.Extensions.dll',("/resource:$core,Core.exe"),('/out:'+(Join-Path $artifactRoot ('Windows/'+$fileName))),(Join-Path $repoRoot 'src/native/NativeApp.cs'),(Join-Path $repoRoot 'src/native/AssemblyInfo.cs'),$versionSource)
  if($role -eq 'Control'){$buildArgs+='/define:CONTROLLER'}
  & $candidateCompiler @buildArgs
  if($LASTEXITCODE){throw "外壳构建失败：$role"}
 }
 Write-Output '外壳已构建（尚未签名）。下一步签外壳，然后运行 Verify-Signatures.ps1。'
 exit
}
$toolRoot=Join-Path $repoRoot '.tools'
[IO.Directory]::CreateDirectory($toolRoot)|Out-Null
$savedEnv=@{}
foreach($name in @('GOBIN','GOOS','GOARCH','CGO_ENABLED')){$savedEnv[$name]=[Environment]::GetEnvironmentVariable($name)}
$staging=Join-Path $artifactRoot ('metadata/engine-build-'+[Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($staging)|Out-Null
Get-ChildItem -LiteralPath (Join-Path $repoRoot 'src/engine') -File | Where-Object {$_.Extension -eq '.go' -or $_.Name -eq 'go.mod'} | Copy-Item -Destination $staging
try{
 $env:GOOS='windows';$env:GOARCH='amd64';$env:CGO_ENABLED='0';$env:GOBIN=$toolRoot
 & $Go -C $staging test ./... -count=1 -timeout 4m
 if($LASTEXITCODE){throw '测试失败'}
 & $Go -C $staging vet ./...
 if($LASTEXITCODE){throw 'go vet 失败'}
 & $Go install github.com/josephspurrier/goversioninfo/cmd/goversioninfo@v1.7.0
 if($LASTEXITCODE){throw '版本资源工具安装失败'}
 $parts=$Version.Split('.')|ForEach-Object{[int]$_}
 $numeric=@{Major=$parts[0];Minor=$parts[1];Patch=$parts[2];Build=$parts[3]}
 foreach($role in @('Control','Agent')){
  $name="$role-core.exe"
  $metadata=@{FixedFileInfo=@{FileVersion=$numeric;ProductVersion=$numeric};StringFileInfo=@{ProductName='VSME Remote Control';ProductVersion=$Version;FileVersion=$Version;FileDescription='User-authorized temporary maintenance engine';CompanyName='VSME Remote Control contributors';OriginalFilename=$name;InternalName=$name;LegalCopyright='Copyright 2026 VSME Remote Control contributors'};VarFileInfo=@{Translation=@{LangID='0409';CharsetID='04B0'}}}
  $jsonPath=Join-Path $staging 'versioninfo.json'
  [IO.File]::WriteAllText($jsonPath,($metadata|ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))
  & (Join-Path $toolRoot 'goversioninfo.exe') -64 -o (Join-Path $staging 'resource_windows_amd64.syso') $jsonPath
  if($LASTEXITCODE){throw '版本资源生成失败'}
  $defaultRole=if($role -eq 'Control'){'controller'}else{'agent'}
  & $Go -C $staging build -trimpath -ldflags "-s -w -X main.defaultRole=$defaultRole -X main.version=$Version" -o (Join-Path $artifactRoot "Core/$name") .
  if($LASTEXITCODE){throw "内部引擎构建失败：$role"}
 }
 foreach($arch in @('arm64','amd64')){
  $env:GOOS='darwin';$env:GOARCH=$arch
  $fileName=if($arch -eq 'arm64'){'苹果被控端-Apple芯片'}else{'苹果被控端-Intel芯片'}
  & $Go -C $staging build -trimpath -ldflags "-s -w -X main.defaultRole=agent -X main.version=$Version" -o (Join-Path $artifactRoot "Mac/$fileName") .
  if($LASTEXITCODE){throw "Mac 交叉构建失败：$arch"}
 }
 Write-Output '内部引擎与 Mac 开发二进制已构建（均未签名）。不要作为可信签名版本发布。'
}finally{foreach($name in $savedEnv.Keys){[Environment]::SetEnvironmentVariable($name,$savedEnv[$name])}}
