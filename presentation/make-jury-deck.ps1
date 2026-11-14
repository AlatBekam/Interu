$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$assets=Join-Path $PSScriptRoot 'assets'
$out=Join-Path $PSScriptRoot 'Interu-Kartika-Cyber-2026.pptx'
$preview=Join-Path $PSScriptRoot 'preview-juri'
New-Item -ItemType Directory -Force -Path $preview | Out-Null

function RGB([int]$r,[int]$g,[int]$b){$r+256*$g+65536*$b}
$bg=RGB 8 20 29; $white=RGB 236 244 243; $muted=RGB 169 190 193
$teal=RGB 44 195 178; $amber=RGB 238 181 96; $rule=RGB 54 79 85

function Rect($s,[double]$x,[double]$y,[double]$w,[double]$h,[int]$c){
  $z=$s.Shapes.AddShape(1,$x,$y,$w,$h);$z.Fill.ForeColor.RGB=$c;$z.Line.Visible=0;return $z
}
function Text($s,[string]$v,[double]$x,[double]$y,[double]$w,[double]$h,[int]$size,[int]$color,[bool]$bold=$false,[int]$align=1){
  $z=$s.Shapes.AddTextbox(1,$x,$y,$w,$h)
  $z.TextFrame.TextRange.Text=$v
  $z.TextFrame.MarginLeft=0;$z.TextFrame.MarginRight=0;$z.TextFrame.MarginTop=0;$z.TextFrame.MarginBottom=0
  $z.TextFrame.WordWrap=-1
  $f=$z.TextFrame.TextRange.Font;$f.Name='Aptos';$f.Size=$size;$f.Color.RGB=$color
  if($bold){$f.Bold=-1}else{$f.Bold=0}
  $z.TextFrame.TextRange.ParagraphFormat.Alignment=$align
  return $z
}
function Pic($s,[string]$file,[double]$x,[double]$y,[double]$w,[double]$h){
  $p=$s.Shapes.AddPicture($file,0,-1,$x,$y,$w,$h)
  $p.Line.Visible=-1;$p.Line.ForeColor.RGB=$rule;$p.Line.Weight=1
  return $p
}
function Base([string]$title,[string]$section,[string]$source=''){
  $s=$pres.Slides.Add($pres.Slides.Count+1,12)
  [void](Rect $s 0 0 960 540 $bg);[void](Rect $s 0 0 6 540 $teal)
  [void](Text $s 'INTERU  /  RUY CYBERSECURITY TEAM' 48 25 720 20 11 $teal $true)
  [void](Text $s $section.ToUpper() 48 62 720 18 11 $muted $true)
  [void](Text $s $title 48 90 860 61 34 $white $true)
  [void](Rect $s 48 499 864 1 $rule)
  if($source){[void](Text $s $source 48 509 804 19 9 $muted)}
  [void](Text $s ([string]$pres.Slides.Count).PadLeft(2,'0') 866 509 46 19 10 $muted $false 3)
  return $s
}
function Label($s,[string]$v,[double]$x,[double]$y,[double]$w=800){[void](Text $s $v $x $y $w 24 12 $teal $true)}

$ppt=New-Object -ComObject PowerPoint.Application
$pres=$ppt.Presentations.Add(0)
$pres.PageSetup.SlideWidth=960;$pres.PageSetup.SlideHeight=540
try{
  # 01 — cover, without an instruction to the presenter.
  $s=$pres.Slides.Add(1,12);[void](Rect $s 0 0 960 540 $bg);[void](Rect $s 0 0 7 540 $teal)
  [void](Text $s 'RUY CYBERSECURITY TEAM' 66 64 700 26 14 $teal $true)
  [void]($s.Shapes.AddPicture((Join-Path $root 'build/icon.png'),0,-1,778,53,110,110))
  [void](Text $s 'INTERU' 66 145 780 100 78 $white $true)
  [void](Text $s 'Workstation pengujian keamanan berbasis aturan' 70 259 785 75 30 $white)
  [void](Rect $s 70 371 818 1 $rule)
  [void](Text $s 'Kartika Cyber Hackathon 2026' 70 394 720 32 20 $muted)
  [void](Text $s 'Aplikasi Windows 1.4.0  ·  bukti yang dapat diperiksa' 70 479 810 30 15 $muted)

  # 02 — the problem stated as the product's task, not as an unsupported market claim.
  $s=Base 'Dari target sampai bukti' 'Tujuan produk'
  [void](Text $s 'Interu menyatukan pekerjaan yang biasanya dilakukan berurutan saat menguji aplikasi web:' 52 175 825 62 23 $white)
  [void](Rect $s 52 260 856 1 $rule)
  [void](Text $s '01' 52 278 65 45 26 $teal $true);[void](Text $s 'Jelajahi halaman dan titik input dalam scope' 122 278 760 48 22 $white)
  [void](Text $s '02' 52 344 65 45 26 $teal $true);[void](Text $s 'Uji respons dengan aturan dan probe terbatas' 122 344 760 48 22 $white)
  [void](Text $s '03' 52 410 65 45 26 $teal $true);[void](Text $s 'Simpan dasar setiap temuan untuk ditinjau ulang' 122 410 760 48 22 $white)

  # 03 — editable product architecture.
  $s=Base 'Cara kerja Interu' 'Alur pemeriksaan' 'Sumber: README.md; src/main/automation.ts; src/shared/automation.ts'
  $items=@(@('SCOPE','Host dan batas'),@('JELAJAH','Browser + crawler'),@('PERIKSA','Rule + Active Scan'),@('BUKTI','Request / response'))
  for($i=0;$i -lt 4;$i++){
    $x=52+$i*222
    [void](Text $s ([string]($i+1)).PadLeft(2,'0') $x 205 90 37 21 $teal $true)
    [void](Text $s $items[$i][0] $x 254 198 42 21 $white $true)
    [void](Text $s $items[$i][1] $x 307 205 55 17 $muted)
    if($i -lt 3){[void](Text $s '→' ($x+182) 253 42 45 25 $teal)}
  }
  [void](Rect $s 52 388 856 1 $rule)
  [void](Text $s 'Hasil masuk ke Operations > Vulnerabilities dengan label confirmed atau suspected. Tidak ada model AI di alur pemindaian.' 52 411 855 68 19 $white)

  # 04 — screenshot from the installed 1.4.0 app.
  $s=Base 'Pentest Automation' 'Satu run, beberapa pemeriksaan' 'Tangkapan layar Interu terpasang 1.4.0 · sumber: presentation/assets/automation-focus.png'
  [void](Pic $s (Join-Path $assets 'automation-focus.png') 50 171 858 315)

  # 05 — browser automation and the honest evidence level.
  $s=Base 'Penjelajahan dan akun uji' 'Automation 1.4.0' 'Sumber: audit/browser-account-verification.json; audit/ten-browser-benchmark.json'
  Label $s 'JELAJAH SATU ORIGIN' 52 176
  [void](Text $s 'Browser bawaan membuka halaman, merender JavaScript, mencatat URL dan form, lalu menyerahkan URL yang ditemukan ke crawler.' 52 207 824 74 22 $white)
  [void](Rect $s 52 305 856 1 $rule)
  Label $s 'AKUN UJI SAAT FORM KOMPATIBEL' 52 328
  [void](Text $s 'Interu dapat membuat identitas sementara, mencoba registrasi dan login, lalu memakai cookie yang diamati untuk scan pada origin yang sama.' 52 359 824 83 22 $white)
  [void](Text $s 'Tes lokal membuktikan alur ini. Pada 10 target evaluasi, tidak ada form registrasi yang cocok; akses login otomatis belum terbukti di sana.' 52 453 840 38 15 $amber)

  # 06 — template library.
  $s=Base 'Rule Engine: 808 template' 'Deteksi berbasis data' 'Sumber: README.md; src/shared/rulepack2025.ts; tangkapan layar aplikasi 1.4.0'
  [void](Text $s '808' 51 177 300 95 72 $teal $true)
  [void](Text $s '28 port/banner  ·  47 HTTP pasif  ·  733 HTTP aktif' 53 275 850 45 23 $white)
  [void](Text $s 'Matcher status, teks, regex, waktu, port, service, dan DSL. Ada extractor, pembanding soft-404, serta korelasi temuan.' 53 329 845 54 18 $white)
  [void](Pic $s (Join-Path $assets 'rule-engine-intro.png') 51 389 857 97)

  # 07 — active scan options, not a claim of complete OWASP coverage.
  $s=Base 'Active Scan' 'Probe pada target berizin' 'Sumber: README.md; src/shared/webvuln.ts; tangkapan layar aplikasi 1.4.0'
  [void](Pic $s (Join-Path $assets 'active-scan-focus.png') 50 170 858 190)
  [void](Text $s 'Probe GET terbatas: SQLi, XSS, LFI, XXE, SSTI, RCE, SSRF, IDOR, CSRF, dan akses sensitif.' 52 385 850 49 22 $white)
  [void](Text $s 'Pemeriksaan memakai baseline atau kontrol pembanding bila tersedia. Sinyal yang belum membuktikan dampak tetap berlabel suspected.' 52 445 850 45 17 $muted)

  # 08 — finding list.
  $s=Base 'Daftar temuan' 'Operations > Vulnerabilities' 'Tangkapan layar Interu terpasang 1.4.0 · target pada gambar: lab lokal'
  [void](Text $s 'Setiap baris menampilkan severity, keyakinan, nama temuan, dan URL target. Baris dapat dibuka untuk memeriksa bukti.' 52 170 850 58 19 $white)
  [void](Pic $s (Join-Path $assets 'vulnerabilities-list-compact.png') 52 247 856 242)

  # 09 — actual selected finding, direct evidence.
  $s=Base 'Temuan dapat ditelusuri' 'Bukti yang bisa diperiksa' 'Tangkapan layar Interu terpasang 1.4.0 · temuan pada lab RUY lokal'
  [void](Pic $s (Join-Path $assets 'finding-detail-compact.png') 52 171 856 323)

  # 10 — lab result with explicit test context.
  $s=Base '150 kasus lab RUY ditemukan' 'Uji regresi internal' 'Sumber: audit/lab-ui-verification.json (UI 1.3.0); testcase/interu50-live.test.ts (sumber 1.4.0)'
  [void](Text $s '150/150' 52 179 340 90 66 $teal $true)
  [void](Text $s 'Active Scan, Rule Engine, dan Pentest Automation masing-masing menemukan seluruh kasus lab melalui uji yang terdokumentasi.' 54 282 340 145 21 $white)
  [void](Pic $s (Join-Path $root 'audit/lab-automation.png') 420 190 488 280)
  [void](Text $s 'Lab ini dibuat untuk Interu; hasilnya tidak mengukur akurasi umum pada aplikasi lain.' 54 451 345 40 15 $amber)

  # 11 — independent UI run on the currently installed version.
  $s=Base 'Uji langsung Interu 1.4.0' 'Lab RUY lokal · 14 November 2026' 'Sumber: audit/installed-automation-live-2026-11-14.json; 175 = temuan lintas keyakinan'
  [void](Text $s '894 request   ·   40 halaman   ·   175 temuan   ·   0 kesalahan transport' 52 158 856 29 20 $white $true)
  [void](Pic $s (Join-Path $assets 'automation-result.png') 52 188 856 302)

  # 12 — independent training targets.
  $s=Base 'Uji pada 10 aplikasi latihan' '7 online · 3 Docker lokal' 'Sumber: audit/multi-target-benchmark.json; audit/ten-browser-benchmark.json'
  [void](Text $s 'DVWA online' 52 182 270 34 22 $white $true)
  [void](Text $s '3 sinyal SQLi MySQL; 1 disclosure file' 315 182 580 50 20 $white)
  [void](Rect $s 52 246 856 1 $rule)
  [void](Text $s 'Juice Shop lokal' 52 270 270 34 22 $white $true)
  [void](Text $s '1 sinyal SQLi SQLite' 315 270 580 50 20 $white)
  [void](Rect $s 52 334 856 1 $rule)
  [void](Text $s 'VAmPI lokal' 52 357 270 34 22 $white $true)
  [void](Text $s 'field password pada JSON daftar pengguna' 315 357 580 58 20 $white)
  [void](Text $s 'Angka temuan lain mencakup header, cookie, dan kandidat. Belum ada ground truth lengkap untuk menghitung precision atau recall.' 52 450 850 42 15 $amber)

  # 13 — operational limits.
  $s=Base 'Batas operasional' 'Menjaga scope dan mutu bukti' 'Sumber: README.md; src/main/automation.ts; src/main/auth.ts'
  Label $s 'TARGET DAN LALU LINTAS' 52 178
  [void](Text $s 'Scope, satu origin per run, batas halaman/request/waktu, jeda antarrequest, dan penghentian saat 429/503 atau scope berubah.' 52 209 850 73 20 $white)
  [void](Rect $s 52 306 856 1 $rule)
  Label $s 'SESI DAN HASIL' 52 327
  [void](Text $s 'Cookie sesi dibatasi origin; nilai rahasia tidak ditampilkan pada panel Automation. Kandidat tidak dinaikkan menjadi kerentanan terkonfirmasi tanpa bukti yang sesuai.' 52 358 850 94 20 $white)
  [void](Text $s 'Alur POST/GraphQL, SSO, MFA, dan logika bisnis kompleks masih memerlukan pengujian lanjutan.' 52 459 850 32 15 $amber)

  # 14 — a handout ending, not presenter instructions.
  $s=Base 'Interu 1.4.0' 'Kesimpulan' 'Kode, lab, dan bukti uji: github.com/AlatBekam/Interu'
  [void](Text $s 'Satu aplikasi Windows untuk menjelajah, menguji, dan memeriksa bukti keamanan web.' 52 176 838 85 28 $white $true)
  [void](Rect $s 52 292 856 1 $rule)
  [void](Text $s 'Sudah dibuktikan' 52 315 330 35 22 $teal $true)
  [void](Text $s 'Paket 1.4.0 terpasang; 300 tes otomatis lulus; 150 kasus lab ditemukan; 10 aplikasi latihan dievaluasi.' 52 356 830 75 20 $white)
  [void](Text $s 'Masih dikembangkan' 52 439 280 30 17 $amber $true)
  [void](Text $s 'Cakupan alur autentikasi, POST/GraphQL, dan benchmark dengan ground truth independen.' 285 439 600 47 17 $muted)

  if(Test-Path -LiteralPath $out){Remove-Item -LiteralPath $out -Force}
  $pres.SaveAs($out,24)
  foreach($sl in $pres.Slides){$sl.Export((Join-Path $preview ('slide-'+([string]$sl.SlideIndex).PadLeft(2,'0')+'.png')),'PNG',1280,720)}
  Write-Output ('saved='+$out);Write-Output ('slides='+$pres.Slides.Count)
}finally{
  $pres.Close();$ppt.Quit()
  [Runtime.InteropServices.Marshal]::ReleaseComObject($pres)|Out-Null
  [Runtime.InteropServices.Marshal]::ReleaseComObject($ppt)|Out-Null
}
