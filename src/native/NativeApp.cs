using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Forms;

static class J {
 public static Dictionary<string,object> Obj(object x){return x as Dictionary<string,object> ?? new Dictionary<string,object>();}
 public static object Get(object x,string k){object v;return Obj(x).TryGetValue(k,out v)?v:null;}
 public static string S(object x,string k){return Convert.ToString(Get(x,k))??"";}
 public static bool B(object x,string k){return Get(x,k) is bool && (bool)Get(x,k);}
 public static object[] A(object x,string k){var a=Get(x,k) as IEnumerable;return a==null||a is string?new object[0]:a.Cast<object>().ToArray();}
 public static string Stamp(string x){DateTime d;return DateTime.TryParse(x,out d)&&d.Year>1900?d.ToLocalTime().ToString("MM-dd HH:mm:ss"):"—";}
 public static Dictionary<string,object> Parse(string s){return new JavaScriptSerializer(){MaxJsonLength=16*1024*1024}.Deserialize<Dictionary<string,object>>(s);}
 public static string Json(object x){return new JavaScriptSerializer(){MaxJsonLength=16*1024*1024}.Serialize(x);}
}

sealed class EngineHost : IDisposable {
 Process process; IntPtr job; public string Url="",Key=""; readonly ManualResetEventSlim ready=new ManualResetEventSlim();
 public Action<string> Log; public string PathName;
 static string Quote(string s){return "\""+System.Text.RegularExpressions.Regex.Replace(s,@"(\\*)\""", "$1$1\\\"")+new string('\\',s.Reverse().TakeWhile(c=>c=='\\').Count())+"\"";}
 public static string Arguments(IEnumerable<string> a){return string.Join(" ",a.Select(Quote));}
 public static string Extract(){
  byte[] data;using(var s=Assembly.GetExecutingAssembly().GetManifestResourceStream("Core.exe"))using(var m=new MemoryStream()){s.CopyTo(m);data=m.ToArray();}
  string hash;using(var sha=SHA256.Create())hash=BitConverter.ToString(sha.ComputeHash(data)).Replace("-","").ToLowerInvariant();
  string root=System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"VSME-RemoteControl-OSS","core-"+hash.Substring(0,16));
  Directory.CreateDirectory(root);var acl=new DirectorySecurity();acl.SetAccessRuleProtection(true,false);
  acl.AddAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User,FileSystemRights.FullControl,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
  acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null),FileSystemRights.FullControl,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));Directory.SetAccessControl(root,acl);
  string path=System.IO.Path.Combine(root,"VSME-Engine.exe");
  if(File.Exists(path)){using(var sha=SHA256.Create())using(var f=File.OpenRead(path))if(BitConverter.ToString(sha.ComputeHash(f)).Replace("-","").ToLowerInvariant()!=hash)throw new IOException("内置引擎校验失败，请勿运行被修改的文件。");}
  else {try {using(var f=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.None))f.Write(data,0,data.Length);}catch(IOException){if(!File.Exists(path))throw;using(var sha=SHA256.Create())using(var f=File.OpenRead(path))if(BitConverter.ToString(sha.ComputeHash(f)).Replace("-","").ToLowerInvariant()!=hash)throw;}}
  return path;
 }
 public static int RunCLI(string[] args){
  string core=Extract();var p=new Process();p.StartInfo=new ProcessStartInfo(core,Arguments(args)){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true,StandardOutputEncoding=Encoding.UTF8,StandardErrorEncoding=Encoding.UTF8};
  p.OutputDataReceived+=(s,e)=>{if(e.Data!=null)Console.WriteLine(args.Length>0&&args[0]=="prompt"?e.Data.Replace(core,Application.ExecutablePath):e.Data);};p.ErrorDataReceived+=(s,e)=>{if(e.Data!=null)Console.Error.WriteLine(e.Data);};p.Start();p.BeginOutputReadLine();p.BeginErrorReadLine();p.WaitForExit();int code=p.ExitCode;p.Dispose();return code;
 }
 public void Start(){
  PathName=Extract();job=CreateJobObject(IntPtr.Zero,null);if(job==IntPtr.Zero)throw new IOException("无法创建任务保护对象");
  var info=new JobLimits();info.Basic.Flags=0x2000;int size=Marshal.SizeOf(info);IntPtr buf=Marshal.AllocHGlobal(size);
  try {Marshal.StructureToPtr(info,buf,false);if(!SetInformationJobObject(job,9,buf,(uint)size))throw new IOException("无法启用关闭即停止保护");}finally{Marshal.FreeHGlobal(buf);}
  process=new Process();process.StartInfo=new ProcessStartInfo(PathName,"--headless --native-ui"){UseShellExecute=false,CreateNoWindow=true,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true,StandardOutputEncoding=Encoding.UTF8,StandardErrorEncoding=Encoding.UTF8};
  process.OutputDataReceived+=(s,e)=>{if(e.Data==null)return;if(e.Data.StartsWith("NATIVE_READY=")){var v=J.Parse(e.Data.Substring(13));Url=J.S(v,"url");Key=J.S(v,"key");ready.Set();}else if(!e.Data.Contains("http://127.0.0.1:")&&Log!=null)Log(e.Data);};
  process.ErrorDataReceived+=(s,e)=>{if(e.Data!=null&&Log!=null)Log(e.Data);};
  process.Start();if(!AssignProcessToJobObject(job,process.Handle)){process.Kill();throw new IOException("无法绑定原生窗口与引擎生命周期");}
  process.BeginOutputReadLine();process.BeginErrorReadLine();
  for(int i=0;i<300&&!ready.Wait(100);i++)if(process.HasExited)throw new IOException("维修引擎未启动，请查看日志；可能已有另一个 v2 窗口。");
  if(Url=="")throw new IOException("启动超时，请检查本程序的防火墙提示。");
 }
 public bool Running {get{return process!=null&&!process.HasExited;}}
 public object Call(string method,Dictionary<string,object> input=null){
  if(Url==""||Key=="")throw new IOException("维修引擎尚未启动");if(input==null)input=new Dictionary<string,object>();input["key"]=Key;
  var req=(HttpWebRequest)WebRequest.Create(Url+"/api/"+method);req.Proxy=null;req.Method="POST";req.ContentType="application/json";req.Timeout=35000;req.ReadWriteTimeout=35000;
  byte[] data=Encoding.UTF8.GetBytes(J.Json(input));req.ContentLength=data.Length;using(var s=req.GetRequestStream())s.Write(data,0,data.Length);
  try{using(var response=req.GetResponse())using(var reader=new StreamReader(response.GetResponseStream(),Encoding.UTF8))return J.Parse(reader.ReadToEnd());}
  catch(WebException e){if(e.Response!=null)using(var reader=new StreamReader(e.Response.GetResponseStream())){string b=reader.ReadToEnd();try{throw new IOException(J.S(J.Parse(b),"error"));}catch(ArgumentException){throw new IOException(b);}}throw;}
 }
 public void Dispose(){
  if(process!=null){try{process.StandardInput.Close();}catch{}try{if(!process.WaitForExit(6500))process.Kill();}catch{} }
  if(job!=IntPtr.Zero){CloseHandle(job);job=IntPtr.Zero;}
  if(process!=null){process.Dispose();process=null;}
 }
 [StructLayout(LayoutKind.Sequential)]struct BasicLimits {public long ProcessTime,JobTime;public uint Flags;public UIntPtr Min,Max;public uint Active;public UIntPtr Affinity;public uint Priority,Scheduling;}
 [StructLayout(LayoutKind.Sequential)]struct Counters {public ulong ReadOps,WriteOps,OtherOps,ReadBytes,WriteBytes,OtherBytes;}
 [StructLayout(LayoutKind.Sequential)]struct JobLimits {public BasicLimits Basic;public Counters IO;public UIntPtr ProcessMemory,JobMemory,PeakProcess,PeakJob;}
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode)]static extern IntPtr CreateJobObject(IntPtr attr,string name);
 [DllImport("kernel32.dll")]static extern bool SetInformationJobObject(IntPtr job,int cls,IntPtr info,uint size);
 [DllImport("kernel32.dll")]static extern bool AssignProcessToJobObject(IntPtr job,IntPtr process);
 [DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr h);
}

sealed class RepairWindow : Form {
 readonly EngineHost engine; readonly bool controller; readonly System.Windows.Forms.Timer timer=new System.Windows.Forms.Timer(){Interval=2000};
 readonly Label status=new Label(),identity=new Label(),target=new Label(),life=new Label(),links=new Label();
 readonly ListView peers=new ListView(),servers=new ListView();
 readonly TextBox command=new TextBox(),output=new TextBox(),sshOutput=new TextBox(),log=new TextBox(),note=new TextBox(),serverName=new TextBox(),serverHost=new TextBox();
 readonly NumericUpDown serverPort=new NumericUpDown(){Minimum=1,Maximum=65535,Value=22,Width=80};
 readonly ComboBox jobs=new ComboBox(){DropDownStyle=ComboBoxStyle.DropDownList,Width=350};
 readonly TabControl tabs=new TabControl(); readonly List<Button> peerButtons=new List<Button>();
 readonly ConcurrentQueue<string> pendingLog=new ConcurrentQueue<string>();
 Dictionary<string,object> state;string selected="",selectedJob="";bool refreshing,appClosing,allowClose,noteLoaded,updating;readonly string wrapper=Application.ExecutablePath;
 static Color Navy=Color.FromArgb(24,39,68),Blue=Color.FromArgb(37,99,217),BG=Color.FromArgb(242,245,250);
 public RepairWindow(EngineHost e,bool isController){
  engine=e;controller=isController;Text="VSME 远程控制 v2.1.1 · "+(controller?"控制主机":"临时被控端");Size=new Size(1160,850);MinimumSize=new Size(920,650);StartPosition=FormStartPosition.CenterScreen;Font=new Font("Microsoft YaHei UI",10);BackColor=BG;
  Icon=SystemIcons.Application;
  var header=new Panel(){Dock=DockStyle.Top,Height=120,BackColor=Navy,Padding=new Padding(18)};
  var heading=new Label(){Text="VSME 远程控制  v2.1.1",Location=new Point(24,13),AutoSize=true,ForeColor=Color.White,Font=new Font(Font.FontFamily,23,FontStyle.Bold)};
  status.SetBounds(26,58,1050,25);status.ForeColor=Color.FromArgb(80,224,174);status.Text="正在启动本机维修通道…";identity.SetBounds(26,85,1080,27);identity.ForeColor=Color.FromArgb(190,210,237);header.Controls.AddRange(new Control[]{heading,status,identity});
  life.Dock=DockStyle.Bottom;life.Height=42;life.Padding=new Padding(14,7,14,0);life.BackColor=Color.FromArgb(229,235,245);life.Text=controller?"关闭本窗口：停止临时副机管理。公开候选版不安装或附带常驻 SSH 权限。":"关闭本窗口：撤销本次临时维修权限并停止本程序任务。不安装服务、不设置开机自启。";
  tabs.Dock=DockStyle.Fill;tabs.Padding=new Point(22,8);Controls.Add(tabs);Controls.Add(header);Controls.Add(life);
  if(controller){BuildPeers();BuildServers();}BuildLocal();var logTab=Tab("运行记录");SetupText(log,true);logTab.Controls.Add(log);
  engine.Log=AddLog;timer.Tick+=async(s,a)=>{DrainLog();await RefreshState();};FormClosing+=OnClosing;Shown+=async(s,a)=>{try{await Task.Run(()=>engine.Start());timer.Start();await RefreshState();}catch(Exception ex){status.Text="启动失败："+ex.Message;AddLog(ex.Message);DrainLog();}};
 }
 TabPage Tab(string title){var t=new TabPage(title){BackColor=BG,Padding=new Padding(15)};tabs.TabPages.Add(t);return t;}
 static void SetupText(TextBox t,bool readOnly){t.Multiline=true;t.ReadOnly=readOnly;t.ScrollBars=ScrollBars.Both;t.WordWrap=false;t.Dock=DockStyle.Fill;t.Font=new Font("Microsoft YaHei UI",10);t.BackColor=readOnly?Color.FromArgb(22,33,52):Color.White;t.ForeColor=readOnly?Color.FromArgb(218,232,251):Color.Black;}
 static Button Button(string title,EventHandler action,bool primary=false){var b=new Button(){Text=title,AutoSize=true,Height=36,MinimumSize=new Size(96,36),Padding=new Padding(8,0,8,0),Margin=new Padding(0,3,8,3),FlatStyle=FlatStyle.Flat,BackColor=primary?Blue:Color.White,ForeColor=primary?Color.White:Navy};b.FlatAppearance.BorderColor=Color.FromArgb(190,205,225);b.Click+=action;return b;}
 static FlowLayoutPanel Bar(){return new FlowLayoutPanel(){Dock=DockStyle.Fill,AutoSize=false,WrapContents=true};}
 static void SetupList(ListView v,string[] labels,int[] widths){v.View=View.Details;v.FullRowSelect=true;v.MultiSelect=false;v.HideSelection=false;v.GridLines=true;v.Dock=DockStyle.Fill;v.Font=new Font("Microsoft YaHei UI",9);for(int i=0;i<labels.Length;i++)v.Columns.Add(labels[i],widths[i]);}
 void BuildPeers(){
  var tab=Tab("临时接入电脑");var grid=new TableLayoutPanel(){Dock=DockStyle.Fill,ColumnCount=1,RowCount=7};grid.RowStyles.Add(new RowStyle(SizeType.Percent,40));grid.RowStyles.Add(new RowStyle(SizeType.Absolute,33));grid.RowStyles.Add(new RowStyle(SizeType.Absolute,47));grid.RowStyles.Add(new RowStyle(SizeType.Absolute,70));grid.RowStyles.Add(new RowStyle(SizeType.Absolute,47));grid.RowStyles.Add(new RowStyle(SizeType.Absolute,36));grid.RowStyles.Add(new RowStyle(SizeType.Percent,60));
  SetupList(peers,new[]{"备注 / 电脑名","系统 / 账号","本机 IP / 来源","接入时间","最近在线","状态"},new[]{185,225,230,110,110,70});peers.SelectedIndexChanged+=(s,a)=>{if(updating)return;selected=peers.SelectedItems.Count==0?"":Convert.ToString(peers.SelectedItems[0].Tag);selectedJob="";UpdateTarget();};grid.Controls.Add(peers,0,0);
  target.Dock=DockStyle.Fill;target.Text="请选择一台在线电脑";target.ForeColor=Blue;target.Padding=new Padding(4,7,0,0);grid.Controls.Add(target,0,1);
  var actions=Bar();AddPeerButton(actions,"读取所选电脑信息",async(s,a)=>await StartJob("info"),true);AddPeerButton(actions,"复制接通提示词",async(s,a)=>await Safe(async()=>{string id=RequireTarget();var v=await Call("prompt",P("agent",id));string p=J.S(v,"text").Replace(engine.PathName,wrapper);Clipboard.SetText(p);AddLog("已复制所选电脑提示词："+id);}));AddPeerButton(actions,"断开所选电脑",async(s,a)=>await Safe(async()=>{await Call("revoke",P("agent",RequireTarget()));await RefreshState();}));actions.Controls.Add(Button("刷新",async(s,a)=>await RefreshState()));grid.Controls.Add(actions,0,2);
  SetupText(command,false);command.WordWrap=true;command.Text="hostname; whoami";grid.Controls.Add(command,0,3);
  var ops=Bar();AddPeerButton(ops,"执行命令",async(s,a)=>await StartJob("shell"),true);AddPeerButton(ops,"取消任务",async(s,a)=>await Safe(async()=>{await Call("cancel",P("agent",RequireTarget(),"job",selectedJob));await RefreshState();}));AddPeerButton(ops,"发送文件…",async(s,a)=>{using(var d=new OpenFileDialog(){Title="选择要发送到所选副机的文件"})if(d.ShowDialog(this)==DialogResult.OK)await StartJob("put",d.FileName);});AddPeerButton(ops,"取回文件…",async(s,a)=>{string path=Ask("从所选副机取回","输入副机文件的绝对路径；接收不会覆盖原文件。","");if(path!=null)await StartJob("get",path);});grid.Controls.Add(ops,0,4);
  jobs.Dock=DockStyle.Fill;jobs.SelectedIndexChanged+=(s,a)=>{if(!updating&&jobs.SelectedItem is Choice){selectedJob=((Choice)jobs.SelectedItem).ID;UpdateOutput();}};grid.Controls.Add(jobs,0,5);SetupText(output,true);grid.Controls.Add(output,0,6);tab.Controls.Add(grid);UpdateTarget();
 }
 void AddPeerButton(FlowLayoutPanel p,string text,EventHandler action,bool primary=false){var b=Button(text,action,primary);peerButtons.Add(b);p.Controls.Add(b);}
 void BuildServers(){
  var tab=Tab("常驻主机 / 服务器");var grid=new TableLayoutPanel(){Dock=DockStyle.Fill,ColumnCount=1,RowCount=4};grid.RowStyles.Add(new RowStyle(SizeType.Percent,38));grid.RowStyles.Add(new RowStyle(SizeType.Absolute,56));grid.RowStyles.Add(new RowStyle(SizeType.Absolute,46));grid.RowStyles.Add(new RowStyle(SizeType.Percent,62));
  SetupList(servers,new[]{"名称","连接地址","服务状态","检测时间","最近可达"},new[]{270,230,160,150,150});grid.Controls.Add(servers,0,0);
  var actions=Bar();actions.Controls.Add(Button("通过 SSH 读取所选信息",async(s,a)=>await Safe(async()=>{string host=ServerHost();sshOutput.Text="正在严格核验 SSH 身份并读取信息…";var v=await Call("ssh-info",P("host",host));sshOutput.Text="SSH 认证成功 · "+host+" · "+J.Stamp(J.S(v,"time"))+"\r\n"+J.S(v,"information");}),true));actions.Controls.Add(Button("复制 SSH 接通提示词",(s,a)=>{try{string host=ServerHost();Clipboard.SetText("本机是获授权控制主机。目标："+host+"。使用既有密钥及严格主机身份核验，不依赖维修窗口。先诊断，再按用户当前请求维修。\r\n& '"+wrapper+"' ssh-info '"+host+"'\r\n& '"+wrapper+"' ssh-run-file '"+host+"' '<本机 UTF8 PowerShell 脚本>'");AddLog("已复制常驻目标提示词："+host);}catch(Exception ex){AddLog(ex.Message);}}));actions.Controls.Add(Button("移除监测项",async(s,a)=>await Safe(async()=>{if(servers.SelectedItems.Count==0)throw new Exception("请选择监测项");await Call("server-remove",P("agent",Convert.ToString(servers.SelectedItems[0].Tag)));await RefreshState();})));grid.Controls.Add(actions,0,1);
  var add=Bar();serverName.Width=180;serverHost.Width=190;serverName.Text="服务器备注";serverHost.Text="10.77.0.13";add.Controls.AddRange(new Control[]{serverName,serverHost,serverPort,Button("添加状态监测",async(s,a)=>await Safe(async()=>{await Call("server-add",P("note",serverName.Text,"host",serverHost.Text,"port",(int)serverPort.Value));await RefreshState();}))});grid.Controls.Add(add,0,2);SetupText(sshOutput,true);sshOutput.Text="端口可达 ≠ SSH 登录成功；不等于 CPU、磁盘健康。\r\n选中一行后点击 SSH 读取信息，才会核验权限并读取系统信息。\r\n关闭此软件不关闭常驻 SSH。";grid.Controls.Add(sshOutput,0,3);tab.Controls.Add(grid);
 }
 void BuildLocal(){
  var tab=Tab(controller?"本机身份 / 接入状态":"连接主控");var panel=new TableLayoutPanel(){Dock=DockStyle.Fill,ColumnCount=1,RowCount=4};panel.RowStyles.Add(new RowStyle(SizeType.Absolute,146));panel.RowStyles.Add(new RowStyle(SizeType.Absolute,92));panel.RowStyles.Add(new RowStyle(SizeType.Percent,100));panel.RowStyles.Add(new RowStyle(SizeType.Absolute,50));
  var connectGroup=new GroupBox(){Text=controller?"连接与分享 · 两台指定主控":"连接主控 · 这里不用填名字",Dock=DockStyle.Fill,Padding=new Padding(12,8,12,8)};
  var connectionLayout=new TableLayoutPanel(){Dock=DockStyle.Fill,ColumnCount=1,RowCount=2};connectionLayout.RowStyles.Add(new RowStyle(SizeType.Absolute,51));connectionLayout.RowStyles.Add(new RowStyle(SizeType.Percent,100));
  connectionLayout.Controls.Add(new Label(){Text=controller?"点“一键复制双主控连接文字”，把整段消息发给被控电脑。\r\n另一主控也可粘贴同一段文字连接本机；地址仍使用原证书核验。":"① 先复制管理员发来的整段连接文字。\r\n② 点“一键粘贴并连接”，会自动读取剪贴板；不要把连接文字填进下面的名字框。",Dock=DockStyle.Fill},0,0);
  var bar=Bar();if(controller)bar.Controls.Add(Button("一键复制双主控连接文字",async(s,a)=>await Safe(async()=>{var v=await Call("share-controller-address");Clipboard.SetText(J.S(v,"text"));AddLog("已核验并复制双主控地址。对方只需复制整段、一键粘贴；不包含私钥。");}),true));
  bar.Controls.Add(Button("一键粘贴并连接",async(s,a)=>await ImportControllerText(),!controller));bar.Controls.Add(Button("高级：手动填写主控 IP",async(s,a)=>await EditControllerAddress()));connectionLayout.Controls.Add(bar,0,1);connectGroup.Controls.Add(connectionLayout);panel.Controls.Add(connectGroup,0,0);
  var noteGroup=new GroupBox(){Text="电脑备注（可选，只填名字，例如：兰）",Dock=DockStyle.Fill,Padding=new Padding(12,10,12,10)};var noteLayout=new TableLayoutPanel(){Dock=DockStyle.Fill,ColumnCount=2,RowCount=1};noteLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));noteLayout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));note.Dock=DockStyle.Fill;note.MaxLength=80;note.Margin=new Padding(0,9,12,0);noteLayout.Controls.Add(note,0,0);noteLayout.Controls.Add(Button(controller?"保存备注并发送本机信息":"保存我的名字",async(s,a)=>await Safe(async()=>{if(note.Text.Contains("VSME-ADDRESS"))throw new Exception("这是连接文字，不是名字。请把它复制后，点上方“一键粘贴并连接”。");var v=await Call("report",P("note",note.Text));AddLog("备注已保存；本机信息发送给 "+J.S(v,"sent")+" 台在线主机。");await RefreshState();})),1,0);noteGroup.Controls.Add(noteLayout);panel.Controls.Add(noteGroup,0,1);
  links.Dock=DockStyle.Fill;links.Padding=new Padding(6,15,6,6);panel.Controls.Add(links,0,2);var close=Bar();close.Controls.Add(Button(controller?"关闭管理窗口（SSH 保留）":"停止并关闭授权",(s,a)=>Close()));panel.Controls.Add(close,0,3);tab.Controls.Add(panel);
 }
 async Task ImportControllerText(){
  try{if(Clipboard.ContainsText()){string value=Clipboard.GetText();if(value.Contains("VSME-ADDRESS1:")||value.Contains("VSME-ADDRESS2:")){await Safe(async()=>{var v=await Call("import-controller-address",P("invite",value));AddLog("已接收 "+J.S(v,"controller")+" 的地址，正在安全连接。");await RefreshState();});return;}}}catch{}
  using(var dialog=new Form(){Text="粘贴主控连接文字",Size=new Size(680,430),StartPosition=FormStartPosition.CenterParent,Font=Font}){
   var label=new Label(){Text="把主控端“一键复制”生成的整段文字粘贴在下面。\r\n自动识别两台主控及地址；仍核验原有证书，不更换控制身份。",Left=18,Top=15,Width=620,Height=55};
   var box=new TextBox(){Multiline=true,ScrollBars=ScrollBars.Vertical,Left=18,Top=80,Width=625,Height=245,MaxLength=16384,Anchor=AnchorStyles.Top|AnchorStyles.Bottom|AnchorStyles.Left|AnchorStyles.Right};
   try{if(Clipboard.ContainsText()){string value=Clipboard.GetText();if(value.Contains("VSME-ADDRESS1:")||value.Contains("VSME-ADDRESS2:"))box.Text=value;}}catch{}
   var apply=Button("导入并连接",(s,a)=>{dialog.DialogResult=DialogResult.OK;dialog.Close();},true);apply.SetBounds(480,340,160,36);apply.Anchor=AnchorStyles.Bottom|AnchorStyles.Right;dialog.Controls.AddRange(new Control[]{label,box,apply});
   if(dialog.ShowDialog(this)==DialogResult.OK)await Safe(async()=>{var v=await Call("import-controller-address",P("invite",box.Text));AddLog("已导入 "+J.S(v,"controller")+" → "+J.S(v,"address")+"，正在核验证书并连接。");await RefreshState();});
  }
 }
 async Task EditControllerAddress(){
  using(var dialog=new Form(){Text="主控地址 · 自动优先，手动兜底",Size=new Size(620,300),StartPosition=FormStartPosition.CenterParent,FormBorderStyle=FormBorderStyle.FixedDialog,MaximizeBox=false,MinimizeBox=false,Font=Font}){
   var explanation=new Label(){Text="IP 变化时会自动查找并核验原有主控证书。\r\n仍连不上时，在这里填主控当前的局域网 IPv4；不能改控制身份。",Left=18,Top=18,Width=575,Height=55};
   var names=new ComboBox(){Left=18,Top=88,Width=245,DropDownStyle=ComboBoxStyle.DropDownList};
   foreach(var c in J.A(state,"connections")){string name=J.S(c,"name");if(name!="")names.Items.Add(name);}
   if(names.Items.Count==0)throw new Exception("尚未配对，请按 README 配置两台主控。");names.SelectedIndex=0;
   var address=new TextBox(){Left=280,Top=88,Width=300,MaxLength=15};
   var hint=new Label(){Text="例如 10.77.0.14（不用输入 https:// 或端口）",Left=18,Top=130,Width=560,Height=30};
   string chosen="",ip="";
   var save=Button("保存并重连",(s,a)=>{chosen=Convert.ToString(names.SelectedItem);ip=address.Text.Trim();if(ip==""){MessageBox.Show(dialog,"请输入地址，或点击“恢复自动查找”。");return;}dialog.DialogResult=DialogResult.OK;dialog.Close();},true);save.SetBounds(430,184,150,36);
   var automatic=Button("恢复自动查找",(s,a)=>{chosen=Convert.ToString(names.SelectedItem);ip="";dialog.DialogResult=DialogResult.OK;dialog.Close();});automatic.SetBounds(250,184,165,36);
   dialog.Controls.AddRange(new Control[]{explanation,names,address,hint,save,automatic});dialog.AcceptButton=save;
   if(dialog.ShowDialog(this)==DialogResult.OK)await Safe(async()=>{await Call("controller-address",P("controller",chosen,"address",ip));AddLog("已更新 "+chosen+" 地址；将核验证书后重连。其他主控连接不变。");await RefreshState();});
  }
 }
 string ServerHost(){if(servers.SelectedItems.Count==0)throw new Exception("先在表格中选择常驻主机或服务器。");var v=J.A(state,"servers").FirstOrDefault(x=>J.S(x,"id")==Convert.ToString(servers.SelectedItems[0].Tag));return J.S(v,"host");}
 object Peer(){return J.A(state,"peers").FirstOrDefault(x=>J.S(x,"id")==selected);}
 string RequireTarget(){var p=Peer();if(p==null||J.B(p,"revoked"))throw new Exception("请先选择在线目标。");return selected;}
 async Task StartJob(string op,string path=""){await Safe(async()=>{string id=RequireTarget();var v=await Call("job",P("agent",id,"op",op,"command",command.Text,"path",path));if(id==selected)selectedJob=J.S(v,"id");await RefreshState();});}
 static Dictionary<string,object> P(params object[] kv){var d=new Dictionary<string,object>();for(int i=0;i<kv.Length;i+=2)d[(string)kv[i]]=kv[i+1];return d;}
 async Task<object> Call(string name,Dictionary<string,object> p=null){return await Task.Run(()=>engine.Call(name,p));}
 async Task Safe(Func<Task> f){try{await f();}catch(Exception ex){AddLog(ex.Message);if(!appClosing)MessageBox.Show(this,ex.Message,"操作未完成",MessageBoxButtons.OK,MessageBoxIcon.Warning);}}
 async Task RefreshState(){if(refreshing||appClosing||!engine.Running)return;refreshing=true;try{var v=await Call("status");ApplyState(J.Obj(v));}catch(Exception ex){status.Text="连接状态读取失败，无法确认："+ex.Message;status.ForeColor=Color.FromArgb(255,208,116);AddLog(ex.Message);}finally{refreshing=false;}}
 public void ApplyState(Dictionary<string,object> v){
  if(appClosing)return;state=v;var m=J.Get(v,"machine");int connectedCount=J.A(v,"connections").Count(c=>J.S(c,"state")=="connected");string own=J.S(m,"name").ToUpperInvariant();bool inbound=J.A(v,"peers").Any(p=>!J.B(p,"revoked")&&J.A(v,"connections").Select(c=>J.S(c,"name").ToUpperInvariant()).Contains(J.S(J.Get(p,"machine"),"name").ToUpperInvariant())&&J.S(J.Get(p,"machine"),"name").ToUpperInvariant()!=own);bool ready=controller?connectedCount>0&&inbound:connectedCount==2;status.Text=controller?(ready?"双向连接已就绪 · 另一主控可互控":"另一主控连接未齐 · 正在自动重试"):connectedCount==2?"2/2 主控已连接 · 两台都可以维修，请保持本窗口打开":connectedCount==1?"1/2 主控已连接 · 可由已连接主控维修；另一台仍在重试":"0/2 主控已连接 · 自动查找中，也可点“一键粘贴并连接”";status.ForeColor=ready?Color.FromArgb(80,224,174):Color.FromArgb(255,208,116);identity.Text=J.S(m,"name")+" | "+J.S(m,"user")+" | "+string.Join(", ",J.A(m,"ips"));if(!noteLoaded){note.Text=J.S(m,"note");noteLoaded=true;}
  updating=true;try{
   peers.BeginUpdate();peers.Items.Clear();foreach(var p in J.A(v,"peers").OrderBy(x=>J.B(x,"revoked"))){var pm=J.Get(p,"machine");var item=new ListViewItem(new[]{(J.S(pm,"note")==""?J.S(pm,"name"):J.S(pm,"note")+" / "+J.S(pm,"name")),(J.S(pm,"os")=="darwin"?"Mac":"Windows")+" / "+J.S(pm,"user"),string.Join(", ",J.A(pm,"ips"))+" / "+J.S(p,"address"),J.Stamp(J.S(p,"joined")),J.Stamp(J.S(p,"last")),J.B(p,"revoked")?"已断开":"在线"});item.Tag=J.S(p,"id");if(J.B(p,"revoked"))item.ForeColor=Color.Gray;peers.Items.Add(item);if(J.S(p,"id")==selected)item.Selected=true;}peers.EndUpdate();
   string serverID=servers.SelectedItems.Count>0?Convert.ToString(servers.SelectedItems[0].Tag):"";servers.BeginUpdate();servers.Items.Clear();foreach(var s in J.A(v,"servers")){var row=new ListViewItem(new[]{J.S(s,"name"),J.S(s,"host")+":"+J.S(s,"port"),J.S(s,"state"),J.Stamp(J.S(s,"checked")),J.Stamp(J.S(s,"last_seen"))});row.Tag=J.S(s,"id");servers.Items.Add(row);if(Convert.ToString(row.Tag)==serverID)row.Selected=true;}servers.EndUpdate();
   links.Text=string.Join("\r\n\r\n",J.A(v,"connections").Select(c=>J.S(c,"name")+" · "+J.S(c,"controller")+"\r\n"+StateName(J.S(c,"state"))+" · 接入 "+J.Stamp(J.S(c,"joined"))+(J.S(c,"error")==""?"":"\r\n"+J.S(c,"error"))))+"\r\n\r\nIP 变化后自动查找原有主控（仅已知局域网段、维修端口及原证书）。\r\n找不到时复制管理员的整段文字，点“一键粘贴并连接”。\r\n断网先停止任务，明确撤销后须重新打开。";
  }finally{updating=false;}UpdateTarget();
 }
 static string StateName(string s){switch(s){case "connected":return "已连接";case "connecting":return "连接中";case "discovering":return "自动查找主控新地址";case "disconnected":return "连接中断";case "closed":return "本次连接已关闭";default:return s;}}
 void UpdateTarget(){var p=Peer();foreach(var b in peerButtons)b.Enabled=p!=null&&!J.B(p,"revoked");target.Text=p==null?"请选择一台在线电脑":"当前目标："+J.S(J.Get(p,"machine"),"name")+" · 会话 "+selected+(J.B(p,"revoked")?"（已断开）":"");updating=true;jobs.Items.Clear();foreach(var j in J.A(p,"jobs"))jobs.Items.Add(new Choice(J.S(j,"id"),J.S(j,"op")+" / "+J.S(j,"state")+" / "+J.S(j,"id")));if(selectedJob==""&&jobs.Items.Count>0)selectedJob=((Choice)jobs.Items[jobs.Items.Count-1]).ID;for(int i=0;i<jobs.Items.Count;i++)if(((Choice)jobs.Items[i]).ID==selectedJob)jobs.SelectedIndex=i;updating=false;UpdateOutput();}
 void UpdateOutput(){var p=Peer();var j=J.A(p,"jobs").FirstOrDefault(x=>J.S(x,"id")==selectedJob);string value=j==null?(J.S(p,"information")==""?"尚无任务。Windows 使用 PowerShell，Mac 使用 zsh。":"副机上报于 "+J.Stamp(J.S(p,"reported"))+"\r\n"+J.S(p,"information")):"状态："+J.S(j,"state")+" / 退出码："+J.S(j,"exit")+" / 字节进度："+J.S(j,"progress")+" / "+J.S(j,"size")+"\r\n"+J.S(j,"output")+(J.S(j,"path")==""?"":"\r\n文件："+J.S(j,"path"));if(output.Text!=value){output.Text=value;output.SelectionStart=output.TextLength;output.ScrollToCaret();}}
 void AddLog(string s){pendingLog.Enqueue(DateTime.Now.ToString("HH:mm:ss")+"  "+s+"\r\n");}
 void DrainLog(){string s;while(pendingLog.TryDequeue(out s)){if(log.TextLength>200000)log.Clear();log.AppendText(s);}}
 async void OnClosing(object s,FormClosingEventArgs e){if(allowClose)return;e.Cancel=true;if(appClosing)return;appClosing=true;timer.Stop();Enabled=false;status.Text="正在停止临时任务并关闭连接…";await Task.Run(()=>engine.Dispose());allowClose=true;Close();}
 string Ask(string title,string label,string value){using(var d=new Form(){Text=title,Size=new Size(590,190),StartPosition=FormStartPosition.CenterParent,FormBorderStyle=FormBorderStyle.FixedDialog,MaximizeBox=false,MinimizeBox=false,Font=Font}){var l=new Label(){Text=label,Left=15,Top=15,Width=550};var t=new TextBox(){Text=value,Left=15,Top=45,Width=550};var b=Button("确定",(s,a)=>{d.DialogResult=DialogResult.OK;d.Close();},true);b.SetBounds(455,87,110,36);d.Controls.AddRange(new Control[]{l,t,b});d.AcceptButton=b;return d.ShowDialog(this)==DialogResult.OK?t.Text:null;}}
 static void CreateHiddenControls(Control c){typeof(Control).GetMethod("CreateControl",BindingFlags.Instance|BindingFlags.NonPublic,null,new[]{typeof(bool)},null).Invoke(c,new object[]{true});foreach(Control child in c.Controls)CreateHiddenControls(child);}
 public void RenderProof(string path){CreateHiddenControls(this);PerformLayout();using(var b=new Bitmap(Width,Height)){DrawToBitmap(b,new Rectangle(Point.Empty,Size));b.Save(path,System.Drawing.Imaging.ImageFormat.Png);}}
 public void RenderConnectionProof(string path){tabs.SelectedIndex=controller?2:0;RenderProof(path);}
 public void SelectProofTarget(string id){selected=id;UpdateTarget();if(RequireTarget()!=id||peerButtons.Any(b=>!b.Enabled))throw new Exception("Native target selection failed");}
 sealed class Choice{public string ID,Label;public Choice(string id,string label){ID=id;Label=label;}public override string ToString(){return Label;}}
}

static class Program {
#if CONTROLLER
 static readonly bool Controller=true;
#else
 static readonly bool Controller=false;
#endif
 [STAThread]static int Main(string[] args){
  // WinExe may have redirected handles but no console; setting OutputEncoding
  // can fail there. Explicit UTF-8 writers preserve Chinese CLI output.
  try{Console.SetOut(new StreamWriter(Console.OpenStandardOutput(),new UTF8Encoding(false)){AutoFlush=true});Console.SetError(new StreamWriter(Console.OpenStandardError(),new UTF8Encoding(false)){AutoFlush=true});}catch{}
  try{
   if(args.Length>0&&args[0]!="--native-smoke"&&args[0]!="--native-layout-smoke")return EngineHost.RunCLI(args);
   Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);
   if(args.Length==3&&args[0]=="--native-layout-smoke"){if(args.Length==0&&!Controller&&MessageBox.Show("此程序允许你配对的两台主控，以当前账户权限执行维修命令和传输文件，并发送电脑名、账户、IP 与系统信息。管理员运行将允许管理员级操作。关闭窗口撤销本次会话，不安装常驻服务。仅在你同意维修时继续。", "确认临时维修授权",MessageBoxButtons.YesNo,MessageBoxIcon.Warning)!=DialogResult.Yes)return 0;
   using(var host=new EngineHost())using(var form=new RepairWindow(host,Controller)){form.ApplyState(J.Parse(File.ReadAllText(args[2],Encoding.UTF8)));form.RenderConnectionProof(args[1]);Console.WriteLine("NATIVE_CONNECTION_LAYOUT=PASS");}return 0;}
   if(!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator)){MessageBox.Show("请右键本程序，选择“以管理员身份运行”。不会自动提权。","需要管理员权限",MessageBoxButtons.OK,MessageBoxIcon.Warning);return 5;}
   if(args.Length==0&&!Controller&&MessageBox.Show("此程序允许你配对的两台主控，以当前账户权限执行维修命令和传输文件，并发送电脑名、账户、IP 与系统信息。管理员运行将允许管理员级操作。关闭窗口撤销本次会话，不安装常驻服务。仅在你同意维修时继续。", "确认临时维修授权",MessageBoxButtons.YesNo,MessageBoxIcon.Warning)!=DialogResult.Yes)return 0;
   using(var host=new EngineHost())using(var form=new RepairWindow(host,Controller)){
    if(args.Length>0){
     host.Start();var s=J.Obj(host.Call("status"));string peerID="";
     if(args.Length>2){
      DateTime deadline=DateTime.UtcNow.AddSeconds(20);object peer=null;
      do{s=J.Obj(host.Call("status"));peer=J.A(s,"peers").FirstOrDefault(p=>string.Equals(J.S(J.Get(p,"machine"),"name"),args[2],StringComparison.OrdinalIgnoreCase)&&!J.B(p,"revoked"));if(peer!=null)break;Thread.Sleep(250);}while(DateTime.UtcNow<deadline);
      if(peer==null)throw new Exception("Native live target did not connect");peerID=J.S(peer,"id");
      var task=host.Call("job",new Dictionary<string,object>{{"agent",peerID},{"op","info"}});deadline=DateTime.UtcNow.AddSeconds(30);object result;
      do{result=host.Call("result",new Dictionary<string,object>{{"agent",peerID},{"job",J.S(task,"id")}});if(J.S(result,"state")=="completed")break;Thread.Sleep(250);}while(DateTime.UtcNow<deadline);
      if(J.S(result,"state")!="completed"||!J.S(result,"output").Contains(args[2]))throw new Exception("Native information task failed");
      s=J.Obj(host.Call("status"));Console.WriteLine("NATIVE_TARGET_INFO=PASS "+args[2]);
     }
     if(J.A(J.Get(s,"machine"),"ips").Length==0)throw new Exception("Native JSON array decoding failed");form.ApplyState(s);if(peerID!="")form.SelectProofTarget(peerID);if(args.Length>1)form.RenderProof(args[1]);Console.WriteLine("NATIVE_SMOKE="+J.Json(new{Role=J.S(s,"role"),Computer=J.S(J.Get(s,"machine"),"name"),Peers=J.A(s,"peers").Length,Servers=J.A(s,"servers").Length,IconLoaded=form.Icon!=null}));return 0;
    }
    Application.Run(form);
   }return 0;
  }catch(Exception ex){if(args.Length>0)Console.Error.WriteLine(ex);else MessageBox.Show(ex.Message,"VSME 启动失败",MessageBoxButtons.OK,MessageBoxIcon.Error);return 1;}
 }
}
