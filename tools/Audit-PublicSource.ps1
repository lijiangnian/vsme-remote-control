#requires -Version 7.0
param([string]$Root=(Join-Path $PSScriptRoot '..'))
$ErrorActionPreference='Stop'
$sourceRoot=[IO.Path]::GetFullPath($Root)
$files=Get-ChildItem -LiteralPath $sourceRoot -Recurse -File | Where-Object {$_.FullName -notmatch '[\\/](\.git|artifacts|\.tools)[\\/]'}
$failures=[Collections.Generic.List[string]]::new()
foreach($file in $files){
 $rel=[IO.Path]::GetRelativePath($sourceRoot,$file.FullName)
 if($file.Extension -in @('.exe','.dll','.zip','.pfx','.p12','.pem','.key','.syso') -or $file.Name -in @('fleet.json','identity.json','servers.json')){$failures.Add("禁止公开的文件：$rel");continue}
 $content=[IO.File]::ReadAllText($file.FullName)
 if($content -match '-----BEGIN (?:[A-Z ]*PRIVATE KEY)|"(?:join_key|private_key|api_token)"\s*:\s*"[^"\s]{8,}"'){$failures.Add("疑似实值密钥：$rel")}
 if($content -match 'ssh-ed25519\s+AAAA[A-Za-z0-9+/]{32,}'){$failures.Add("实值 SSH 主机绑定：$rel")}
}
if($failures.Count){$failures;throw '公开源码检查失败；不输出密钥内容。'}
Write-Output "PUBLIC_SOURCE_AUDIT=PASS ($($files.Count) text files). 此门禁不代替人工安全审阅。"
