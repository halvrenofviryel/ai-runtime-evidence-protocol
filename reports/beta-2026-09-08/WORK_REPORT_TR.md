# AIREP v0.2.0-beta.1 uygulama ve birleştirme raporu

Çalışma dönemi: 8–9 Eylül 2026 (Europe/Istanbul). Hedef GitHub reposu:
`halvrenofviryel/ai-runtime-evidence-protocol`.

**Sonuç: beta uygulaması teknik olarak tag hazırlığına uygun.** Son CI eşdeğeri
koşuda **54/54 komut başarılı**; yeni beta testleri **39/39 başarılı**. Hosted CI,
GitHub push, tag, release veya DOI yayını yapılmadı. Stable bağımsızlık kapıları
açık; bunlar beta başarısı diye sunulmadı.

## 1. İncelenen dizinler ve birleştirme kararı

Tek beta çalışma noktası: `/mnt/data/claude/airep-v02-beta-prep`,
`release/v0.2-beta-prep` dalı. Başlangıç commit'i
`1400aa2451d0b94d07a5672a0baf404bac8448c8`. GitHub main salt okunur olarak
kontrol edildi: `a3973ce3b6ad984635867a2bb52d83c472e5c0cb`; beta dalı bunun
üzerindeki yerel, daha ileri çalışmaları içeriyordu.

| Kaynak | Başlangıç bulgusu | Yapılan işlem |
|---|---|---|
| `ai-runtime-evidence-protocol` | `research/nist-acder`, `449f4fb`; beta dalından daha eski taban, bağımsız araştırma işi ve üretilmiş dist/dependency dosyaları | Araştırma dalı değiştirilmedi; beta kodu yanlışlıkla bu dala karıştırılmadı |
| `airep-v02-beta-prep` | AD-16, profil kararı N-01, normatif sınıf metni ve r2 commit'leri mevcut; AD-17/r3 taslakları yerel ve henüz commit edilmemiş | Kanonik çalışma noktası seçildi; mevcut işler korundu ve tamamlandı |
| `.airep_fresh` | `779c71c`, eski class-verification integration snapshot; yerel preflight dosyası | Git bilgisi yalnız bu komuta özgü safe.directory ile okundu; global config değiştirilmedi; eski snapshot korundu |
| `.airep_v3p`, `.airep_v3n`, `.airep_v4p`, `.airep_v4n`, `.airep_v5n`, `.airep_verify`, `.airep_verify_n` | Eski verifier/snapshot/çıktı kopyaları | Kaynak dosyaları hash ile envantere alındı; eski ölçümler silinmedi veya yeni beta diye yeniden adlandırılmadı |
| `airep-wt-py-final`, `airep-wt-py-final2` ve Git'in kaydettiği `/tmp/...` W1 worktree'leri | Eski W1 evaluator geliştirme zinciri, daha yeni Erratum-8 dalları da mevcut | En son ilgili Python/Node E8 dosyaları exact-byte olarak tek beta repo ağacına alındı |
| `airep-release-artifacts` | Alpha tar/zip, checksum, eski branch bundle ve restore notu | Tümü yerinde korundu; beta çıktısıyla değiştirilmedi |
| `phionyx-rge-airep` ve diğer downstream/vendor kopyaları | Ayrı entegrasyon çalışmaları / v0.1 projection / test kopyaları | Beta için özel monorepo bağımlılığı haline getirilmedi; kapsam dışı projeler değiştirilmedi |

Erişilebilen `/mnt/data`, `/home/toygar/Desktop` ve `/tmp` kaynakları tarandı;
korumalı işletim sistemi dizinlerine erişildiği iddia edilmiyor. Ayrıntılı Git
worktree ve dizin listesi [inventory.json](inventory.json); eski snapshot'ların
867 kaynak dosyası [historical-snapshots.json](historical-snapshots.json).
İlk envanter alınırken oluşturulan `reports/` girdisi denetimin kendi çıktısıdır,
önceden var olan kullanıcı işi olarak sayılmadı.

Tamamlanmış işlerin yeniden yapıldığı iddia edilmiyor: normatif
`CONFORMANCE_CLASSES.md` zaten `19602eb` ile vardı; N-01 profil kararı `3826ee8`,
AD-16 ve önceki readiness matrisi de yereldi. Bunlar kullanıldı. “Normatif sınıf
metni yok / producer başlamadı” diyen güncel durum belgeleri gerçek beta durumuna
uyarlandı; eski readiness metni ayrıca byte-identical tarihsel snapshot olarak
korundu.

W1 birleştirmesi: Python `c589e7a` ve Node `c247a25` Erratum-8 kaynaklarından
**9 dosya**, `spec/airep/v0.2/interop/` altında toplandı. Tam commit ve dosya
SHA-256 kayıtları [consolidated-imports.json](consolidated-imports.json).
Mevcut bağımsız authoring geçmişi yeniden yazılmadı; bunların bu oturumda bağımsız
ajanlarca yazıldığı ya da yeni bir dış interoperability sonucu ürettiği iddia edilmedi.
Comparator'ın `parity/` geçici çalışma dizinlerindeki mutlak input symlink'leri
release paketinden dışlandı; complete loglar, `parity.json` ve `parity.txt`
korundu. Runner bu geçici inputları kendi scratch dizininde yeniden üretir;
temiz clone eski `/tmp` içeriklerine bağlı değildir.

Eski çalışma dizinleri/arşivler silinmedi: birleştirme, güncel geliştirme yüzeyini
tek bir Git repo ağacına almak şeklinde yapıldı.

## 2. Eklenen ve değiştirilen dosyaların kesin listesi

Tüm yol ve SHA-256 bilgileri [CHANGED_FILES.md](CHANGED_FILES.md) ve
[changed-files.json](changed-files.json) içinde; liste sadece örnek dosyalar değil,
Git başlangıç HEAD'ine göre tüm ekleme/değişiklikleri ve rapor kanıt dosyalarını
kapsar. Mevcut taslaklar ve birleştirilen W1 kaynakları ayrı kökenle işaretlidir.

Başlıca uygulama dosyaları: `tools/airep_v02/{producer,json_input,basis,profiles,
verify,reconcile,__main__,__init__}.py`, `verify_node.mjs`; yaşam döngüsü
`examples/v02/run_lifecycle.py`, 11 fixture seti ve test-only profil basis'i;
`tests/v02/test_beta.py`; CI/yerel runner ve quickstart kontrol script'leri.
Belge yüzeyi: `SPEC.md`, `QUICKSTART.md`, `VERIFICATION.md`, `RECONCILIATION.md`,
`BETA_READINESS.md`, `RELEASE_STAGES.md`, beta release notes, root CHANGELOG,
README/status/CITATION güncellemeleri ve bu rapor.

## 3. Kesin normatif değişiklikler ve korunmuş kurallar

* `spec/airep/v0.2/SPEC.md` normatif giriş noktası oldu. Kabul edilmiş şema,
  AD-17, sınıf ve r3 sözleşmelerini açık sahiplik/öncelik kurallarıyla bağlar.
  Önceden donmuş `INTEGRITY.md` tek byte-authoritative kaynak olarak kalır.
* Yeni `RECONCILIATION.md`, beta aracının referans çözümleme, talimat gruplama,
  çift taraflı control, TOCTOU, Effect→Execution/Decision bağlama, observer ve
  çoklu talimat/Execution değerlendirme sözleşmesini tanımlar. SATISFIED,
  FAILURE, MISSING, NOT_EVALUATED, INDETERMINATE ayrı sonuçlardır; yeni bir
  assurance class eklenmez. Kayıtların raporladığı olgular değerlendirilir,
  gerçek dünya doğruluğu veya bütün geçmişin tamlığı çıkarılmaz.
* Zincir kuralı AD-05'in monoton sıralamasını korur. Sıfırdan başlayıp birer
  artmak reference producer tercihidir; kabul edilmiş wire kuralına keyfî
  “mutlaka ardışık sequence” zorunluluğu eklenmedi. Genesis zero digest'i
  mevcut kabul edilmiş schema-design kaynağındandır.
* Önceden hazırlanmış AD-17 metni ve r3 sözleşmesi byte-identical korundu;
  uygulanmayan JSON/binary64 ve profil yüzeyleri koda taşındı. AD-17 §6.4'ün
  “yuvarlama sınır dışını kabul edilir hale getiremez” hükmü ham `sequence`
  token'ında uygulanır; genel profil sayıları binary64 kurallarını kullanır.
* r3 §R3.4.5'in son cümlesindeki “none … PASS/FAIL” ifadesinin, aynı bölümün
  kabul edilen ilk iki pozitif probe'una değil reddedilen/unusable probe'lara
  uygulandığı `VERIFICATION.md` içinde açık editoryal açıklamayla kaydedildi.
  r3'ün kabul edilen basis→PASS/FAIL kuralı değiştirilmedi; donmuş metin/digest
  sessizce düzeltilmedi.
* AD-01'in alpha'ya migration tooling dahil eden eski cümlesi yerinde bırakıldı;
  alpha'da bunun bulunmadığı açıkça kayda geçirildi. Migration modeli korunup
  tooling beta dışına taşındı. `RELEASE_STAGES.md` beta implementation gate,
  RC programme/candidate gate ve stable independence gate ayrımını yapar.
  AD-16'nın Core/companion sınırı ve AD-15/16'nın dış bağımsızlık şartları azaltılmadı.
* Sınıf anlamları, pure Ed25519 suite, domain tag'leri, hash/signature preimage'ları,
  wire version `0.2`, beş kabul edilmiş şema ve v0.1 semantiği değiştirilmedi.
  Kendi beyan ettiği key Authenticated sağlamaz; hiçbir sınıf truth assurance vermez.

## 4. Kesin uygulama değişiklikleri

Producer dört aileyi üreten küçük Python kütüphanesi ve `python3 -m tools.airep_v02`
CLI'si olarak uygulandı. Required core alanları, UUID varsayılan kimlikleri,
sequence ve previous cursor'ı, RFC 8785/JCS, frozen tag/hash ve doğrudan pure
Ed25519 imzası oluşturur. `emit-decision`, `emit-control`, `emit-execution`,
`emit-effect`, `keygen`, `digest`, `verify`, `reconcile` komutları vardır.
Başarısız emission cursor'ı ilerletmez; çıktı/key dosyaları varsayılan olarak
ezilmez. Payload core alanlarını override edemez. Crypto davranışı wire alg'den
seçilmez. `digest_bytes` ve açık `digest_json` ayrıdır.

Örnek gerçek bir yerel dosya sınırını kullanır: karar → issuer dispatch dosyası
→ receiver read/receipt → okunan talimatın eylemini uygulama → state dosyasını
okuyup Effect üretme. Üç ayrı zincirde explicit record references, instruction ID/
digest, authorized/executed digest ve observer ilişkisi bulunur. Bütün roller ve
policy örneği first-party'dir; public test seed'leri gerçek dış bağımsızlık
kanıtı olarak sunulmaz. Tam örnek beş Authenticated kayıt verir; witness olmadığı
ve toplam hedef envanteri verilmediği açıkça görünür.

Reconciler schema/hash admission'dan sonra gerçek graph bağlarını kontrol eder;
invalid kayıtlar olgu çözümleme için kullanılmaz, global duplicate kimlikte bir
kazanan seçilmez. Her talimat ve her Execution'ın Effect kapsamı ayrı
incelenir. Eksik receipt, eksik execution, mismatch, eksik Effect, same_executor,
kanıtlanamayan independent ve dört bozuk aile fixture'ı dahil 11 set vardır.
Ek testler wrong-family/chain refs, çoklu instructions/Executions, explicit
failed/suppressed olaylar ve kısmi gözlemi kapsar.

Beta Python/Node adapter'ları frozen r1 engine'leri koruyarak AD-17 admission ve
r3 profil-basis değerlendirmesini ekler. Duplicate member, Unicode domain,
nonfinite sayılar, raw integer bounds, exact basis/registry digest, symlink/root
containment, self-contained refs, pinned Draft 2020-12, annotation-only format,
unknown-profile NOT_EVALUATED ve caveat kanalları uygulanır. İki adapter bu
çalışmada birlikte geliştirildi: yeni independent-authoring iddiası yoktur.

## 5. Çalıştırılan testler ve kesin sonuçlar

Asıl son komut:

```bash
python3 scripts/check_beta.py --with-v01-typescript --out reports/beta-2026-09-08/release-validation
```

**54/54 komut exit 0.** Her alt komutun exact argv/cwd/exit/log bağlantısı
[TEST_COMMANDS.md](TEST_COMMANDS.md); makine kaydı [release-validation/results.json](release-validation/results.json).
Log SHA-256'ları bu JSON'da, test edilen kaynak dosya kimlikleri
[release-validation/source-basis.json](release-validation/source-basis.json) içindedir. Ölçüm geçici bir
repo kopyasında yapıldı; yeniden üretim script'leri kanonik ağaçtaki donmuş
kanıt dosyalarının üstüne yazmadı.

| Grup | Sonuç |
|---|---|
| Python / Node runtime | Python 3.12.3; Node v20.19.6 |
| Frozen integrity vectors | Python/Node byte agreement; comparator ve ekstra-field negatif kontrolü başarılı |
| Stage-4 integrity / adversarial | İki verifier, determinism, A1–A13 ailesi, v0.1 auxiliary ve envelope negatif kontrolü başarılı |
| Schema validation | Python 117 ve Node 117 fixture; parity ve corruption gate proof başarılı |
| Historical class verification | 60-case corpus, selfchecks/errata/process exit/parity comparator ve negatif proof'lar başarılı |
| Yeni beta testleri | 39 test başarılı; parameterized dört aile/class/tamper vakaları ve 60 tarihsel vaka yeniden kontrol edildi |
| JCS ek sayı örneklemi | 4.096 sabit-seed binary64 bit örneğinin sonlu altkümesi Python/Node canonical bytes eşit; tüm binary64 uzayı için matematiksel ispat iddiası yok |
| v0.1 pytest | 124 passed; ayrıca standalone conformance, JCS/parity/Trusted testleri başarılı |
| v0.1 producer/regeneration | Regeneration drift yok; TypeScript build başarılı, 3 kayıt iki reference verifier tarafından kabul edildi |
| Eski crypto-projection regresyonları | 12/12 başarılı |
| Birleştirilen W1 Python | 423 test; 0 failure/error; 1 platforma özgü branch skip; 20/20 zorunlu block measured |
| Birleştirilen W1 Node | 2.329 assertion passed; 0 failed/skipped; üretilemeyen tamamlayıcı platform branch'i NOT MEASURED |
| Gerçek lifecycle / quickstart | Keygen, beş emission adımı, Python/Node verify, reconcile ve no-receipt negatif örneği başarılı |
| Belge ve frozen-byte denetimi | 12 okuma-yolu belgesi; 1.919 tarihsel dosya byte-identical; 0 hata |

W1'in skip/NOT MEASURED ayrıntısı gizlenmedi: Python'da `os.scandir` Unicode-native
isim verir, lossless raw-byte dalı bu API ile üretilemiyor; Node'da buffer isimli
`readdirSync` ters dalı üretilemiyor. Her iki lane'in zorunlu block ölçümleri
mevcut; bu platform branch'leri PASS diye yeniden etiketlenmedi.

İlk tam koşu da [full-round1/results.json](full-round1/results.json) ile
48/48 başarılıydı. Sonrasında eklenen raw sequence ve developer-path kontrolleri
son 54 komutluk koşuyla ölçüldü. Hosted GitHub Actions **NOT_RUN**: yerel CI eşdeğeri
sonuç, hosted koşu diye sunulmadı.

## 6. Bulunan hatalar, düzeltmeler ve başarısız ölçümlerin korunması

| Bulgu | Kanıt / Düzeltme / Regresyon |
|---|---|
| R1 parser duplicate alanları map'e düşürüp büyük sayılarda Python/Node modelini ayırıyordu | [pre-fix-json.json](pre-fix-json.json); beta recursive duplicate/Unicode/BOM/finite binary64 admission; iki runtime raw-input ve sayı testleri |
| R1 observer yolu authentic Decision'ı Execution önkoşulu olarak kabul edebiliyordu | [pre-fix-observer.json](pre-fix-observer.json): eski sonuç independent; beta actual Execution type + global unique identity kontrolü; wrong-family/duplicate regresyonları |
| Ham sequence sınır dışından yuvarlanıp kabul edilebiliyordu | [pre-fix-sequence-bounds.json](pre-fix-sequence-bounds.json): `9007199254740991.1` ve `-1e-400`; iki adapter tam ham-token bound kontrolü, genel profil binary64 davranışı korunarak düzeltildi |
| İlk beta CLI malformed artifact'te traceback veriyordu; reconciler invalid artifact exception'ını kaçırıyordu | [new-tests-initial.log](new-tests-initial.log); `RunInvalid` doğru sınırda yakalandı, no-partial-result ve malformed admission regresyonları eklendi |
| İlk reconciler destekleyici referans listelerinin sırası input permütasyonuyla değişiyordu | Aynı ilk başarısız log; evidence referansları UTF-8 kimlik sırasına kondu; permutation testi başarılı |
| Yeni dokümanların bazı repo-relative linklerinde bir fazla `..` vardı | [pre-fix-doc-links.log](pre-fix-doc-links.log); linkler düzeltildi; bütün okuma-yolu auditi tekrar geçti |
| Tarihsel Node default schema yolu URL pathname kullanıyordu; boşluklu clone konumu portable değildi | Beta launcher resolved explicit schema-dir geçirir; boşluklu clone'da Python/Node testi başarılı; eski byte-pinned engine değiştirilmedi |
| İlk smoke harness, standalone projection test script'ini pytest olarak çağırıp exit 5 aldı | [baseline/43.log](baseline/43.log); test script'inin belgelenmiş doğrudan komutu kullanıldı, 12 gerçek assertion ölçüldü; test gevşetilmedi |
| İlk Node alt süreç sonuçları sandbox EPERM yüzünden boş geliyordu | İlk [baseline](baseline/) korundu. Minimal Node spawn reproducer EPERM gösterdi; izinli ortamda yeniden koşuldu. Denenen geçici Node revision kaldırıldı; finalde frozen engine aynı byte'larla başarılı. Bu ortam hatası protocol başarısızlığı veya stdout-fix başarısı diye sunulmadı |

İlk yeni test koşusu 33 testte **2 failure + 1 error** içeriyordu; sonraki 33 ve
38 testlik koşular, ardından 39 testlik final koşu ayrı loglarda korundu.
Eski Joel/Certisyn evidence'ı, Emek'in v0.1 sonucu, önceki failing runs, frozen
hash'ler veya corpus revision'ları tekrar skorlanmadı ya da değiştirilmedi.

## 7. Kalan beta sınırlamaları

Producer first-party ve single-writer reference cursor'dır; production HSM/KMS,
concurrent durable ledger, remote checkpoint veya gerçek dünya truth garantisi
sağlamaz. Caller input/observations ve uygulama digest/projection tanımları açıkça
verilmelidir. Reconciler yalnız verilen evidence set'ini inceler; URI fetch etmez,
toplam hedef envanteri almaz ve bütün geçmişin tamamlığını PASS yapmaz. Dört
artifact family ayrı class sonuçlarını korur. Demo bağımsız witness sağlamaz;
public test policy gerçek organizasyonel bağımsızlığı kanıtlamaz.

Profil yüzeyi generic, self-contained ve test-only basis örneklidir; SCITT/AuthZEN
E2E, tam MCP/A2A/OTel kataloğu, donanım attestation, migration projector ve regulatory
crosswalk yenilemesi yoktur. Beta API repo-root modülü/CLI'sidir; ayrı PyPI paketi
veya başka bir dilde producer yayınlandığı iddia edilmez. Eski doğrudan r1
engine'lerin kapsamı tarihi olarak kalır; yeni giriş için beta adapter'ları kullanılır.

## 8. Kalan RC engelleri / program işleri

Daha geniş cross-implementation/producer-output corpus; exact candidate wire/basis
freeze ve release discipline; amaçlanan SCITT registration/receipt ve AuthZEN
reference E2E exercises; yeni aday üzerine daha geniş dış uygulama ölçümü.
Bunlar beta uygulamasını durdurmaz. AD-16 uyarınca companion çalışmalarının kendi
lifecycle'ı Core wire/stable kapısına sessizce dönüştürülmez. Migration tooling
beta dışındadır; model korunmuştur.

## 9. Kalan stable engelleri

Aynı frozen v0.2 adayında en az iki producer ve en az bir genuinely non-maintainer
producer; bunların gerçekten ürettiği output'lar; aynı adayda non-maintainer
consumer/verifier; her qualifying producer'ın çıktıları, adversarial ve
reconciliation corpus'unun iki reference verifier ve qualifying dış consumer
rollerinde geçmesi; final same-basis parity/frozen identity/reproduction.

Tek tarihsel dış v0.2 consumer sonucu **17 AGREE / 1 DISAGREE**, expected-blind
değil ve önceki r1/handoff temelinde. Emek'in v0.1.2 producer sonucu ayrı sürüm ve
ayrı kanıt sınıfı. Aynı sürüm third-party v0.2 producer→consumer sonucu **yok**.
Bu oturum bunları bağımsız interoperability PASS'e çevirmedi.

## 10. Tag değerlendirmesi ve teslim durumu

**Teknik değerlendirme: v0.2.0-beta.1 tag hazırlığı için hazır; kalan beta
uygulama engeli yok.** Normal maintainer diff/commit incelemesi, son commit'te
hosted CI ve yetkili yayın adımları release checklist'inde açıkça bulunur.
Bunlar gerçekleştirilmiş gibi yazılmadı. Beta source/status/release notes/changelog,
readiness evidence, tag/archive talimatları ve DOI kontrol listesi hazırdır.
Alpha DOI beta'ya atanmadı; CITATION beta target version ve mevcut concept DOI'yi
kullanır, actual release date/yeni version DOI yayın aşamasında girilecektir.

Kod ve tüm kayıtlar tek `release/v0.2-beta-prep` çalışma dalında toplanmıştır.
Bu hazırlık GitHub'a push, tag veya release publish etmez. Dış kişilere mesaj
veya e-posta gönderilmedi; bağımsız katkı ya da başarı üretilmedi.

Tam release-validation koşusundan sonra yalnızca README açıklaması ve rapor/readiness
sonuç kayıtları tamamlandı; uygulama/test/runner kaynakları değişmedi.
[post-measurement-doc-basis.json](post-measurement-doc-basis.json) bu ayrımı
hash ile gösterir; [post-handoff-doc-audit.log](post-handoff-doc-audit.log) son
belgelerin link/preservation kontrolünün geçtiğini kaydeder.

Yerel teslim commit mesajı: `feat: prepare AIREP v0.2.0-beta.1 implementation target`.
Commit kimliği, bu raporu taşıyan beta dalında `git log -1 --format=%H` ile
alınabilir. Bu yerel Git teslimi bir tag, push, hosted CI veya release yayını
olduğu anlamına gelmez.
