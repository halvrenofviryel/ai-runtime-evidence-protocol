# AIREP v0.2.0-beta.1 yayın incelemesi — 2026-09-09

Kullanıcı beta implementasyon raporunu inceleyip dalın gönderilmesini, hosted CI
sonrasında tag ve GitHub prerelease yayımlanmasını yetkilendirdi. Yeni özellik
geliştirme kapsam dışıdır. Yeni Zenodo version DOI'sini kullanıcı alacaktır;
alpha DOI beta için kullanılmayacaktır.

## İncelenen temel

* Yerel beta implementasyonu: `5f0afc416712a2ecd6c266900d1a54789ddf124e`.
* GitHub `main`: `a3973ce3b6ad984635867a2bb52d83c472e5c0cb`.
* Beta dalı main'in devamıdır; çatışan uzak commit yoktur. Önceden kabul edilmiş
  AD-16, N-01, sınıf sözleşmesi ve r2 commit'leri de bu yayınla main'e taşınır.
* Producer, CLI, verifier adapter, reconciler, CI runner ve release belgeleri
  incelendi. Bu inceleme bağımsız üçüncü taraf incelemesi veya insanın GitHub
  review onayı olarak sunulmaz.
* Önceki 54/54 yerel komut ve 39/39 beta testinin ham kanıtları
  [implementasyon raporunda](../beta-2026-09-08/WORK_REPORT_TR.md) korunur.
  Hosted CI bunlardan ayrı, yayımlanacak commit üzerinde ölçülecektir.

## Bu turdaki düzeltmeler

1. README'nin alt bölümünde kalmış “v0.2 producer implementation yok” cümlesi
   bulundu. Dört aile için birinci taraf producer'ın bulunduğu ve aynı sürüm
   üçüncü taraf producer→consumer sonucunun bulunmadığı şeklinde düzeltildi.
2. Citation bölümünün bütün geliştiricileri v0.1 DOI'sine yönlendiren cümlesi
   düzeltildi. Beta tag/release bağlantısı verildi; yeni DOI alınana kadar
   alpha version DOI'sinin kullanılamayacağı açıklandı.
3. `CITATION.cff`, `CHANGELOG.md`, `RELEASE_NOTES_BETA_1.md` için yayın tarihi
   2026-09-09 olarak hazırlandı. Concept DOI ve eski version DOI'leri korundu.
4. `BETA_READINESS.md`, önceki NOT_RUN hosted durumunu tarihsel ölçüm olarak
   koruyup ayrı yayın kanıtına yönlendiriyor. Önceki rapor yeniden yazılmadı.

Normatif protokol, producer/verifier/reconciler kodu, frozen dosyalar, dış kanıtlar
ve önceki başarısız ölçümler bu yayın turunda değiştirilmedi. Yeni özellik veya
araştırma eklenmedi.

## Yayın kayıtlarının yeri

Bu dosya tag öncesi incelemeyi kaydeder. Sonraki hosted run URL'leri, kesin commit,
tag, arşiv SHA-256 değerleri ve yayın sonucu
[GitHub prerelease](https://github.com/halvrenofviryel/ai-runtime-evidence-protocol/releases/tag/v0.2.0-beta.1)
üzerindeki `PUBLICATION_REPORT_TR.md`, `hosted-ci.json` ve `SHA256SUMS.txt`
eklerinde saklanacaktır. Böylece test edilen commit'e kendi sonradan oluşan
run kimliğini eklemek için tag değiştirilmez. Başarısız hosted denemeler olursa
son başarılı ölçümle birlikte saklanacaktır.

Beta implementation readiness, bağımsız interoperability readiness değildir.
RC/stable sınırları [RELEASE_STAGES.md](../../spec/airep/v0.2/RELEASE_STAGES.md)
ile aynen korunur. Zenodo yayını kullanıcının ayrı adımıdır; GitHub release
yayımlanmış olsa bile DOI yayımlandı şeklinde raporlanmayacaktır.
