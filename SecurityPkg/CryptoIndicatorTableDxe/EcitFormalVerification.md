# ECIT Formal Verification Constraints and Properties

## Reference

UEFI Specification, Section 37 "Secure Technologies" — EFI Crypto Indicator Table (ECIT).

---

## 1. Table Header Structural Invariants

### P1.1 Signature Integrity

```
∀ table : EFI_CRYPTO_INDICATOR_TABLE,
  table.Signature == "ECIT"
```

The 4-byte Signature field SHALL equal the ASCII string `"ECIT"` (0x45434954).

### P1.2 Length Consistency

```
∀ table : EFI_CRYPTO_INDICATOR_TABLE,
  table.Length == sizeof(ACPI_SDT_HEADER) + sizeof(ECIT_SPECIFIC_FIELDS) + Σ(entry[i].EntryLength for i in 0..NumberOfEntries-1)
```

The Length field SHALL equal the total byte size of the entire table including the ACPI SDT header, ECIT-specific fields (NumberOfEntries + Reserved[3]), and all entry data.

### P1.3 Version Validity

```
∀ table : EFI_CRYPTO_INDICATOR_TABLE,
  table.Version == EFI_CRYPTO_INDICATOR_TABLE_VERSION  (== 1)
```

### P1.4 Checksum Zero-Sum

```
∀ table : EFI_CRYPTO_INDICATOR_TABLE,
  let bytes = (UINT8*)&table,
  Σ(bytes[i] for i in 0..table.Length-1) mod 256 == 0
```

The byte-wise sum of the entire table (Length bytes starting from the table base) SHALL equal zero modulo 256.

### P1.5 Reserved Fields Zero

```
∀ table : EFI_CRYPTO_INDICATOR_TABLE,
  table.Reserved[0] == 0 ∧ table.Reserved[1] == 0 ∧ table.Reserved[2] == 0
```

---

## 2. Entry Structural Invariants

### P2.1 Entry Count Matches Actual Entries

```
∀ table : EFI_CRYPTO_INDICATOR_TABLE,
  |{entries iterable within table.Length}| == table.NumberOfEntries
```

The number of entries reachable by iterating EntryLength offsets from the first entry until exhausting (table.Length - header_size) bytes SHALL equal NumberOfEntries.

### P2.2 Entry Length Minimum Bound

```
∀ entry : EFI_CRYPTO_INDICATOR_ENTRY,
  entry.EntryLength >= sizeof(EFI_CRYPTO_INDICATOR_ENTRY)
```

EntryLength SHALL be at least sizeof(EFI_GUID) + sizeof(UINT16) + sizeof(Reserved[6]) = 24 bytes.

### P2.3 Entry 8-Byte Alignment

```
∀ entry[i] where i < NumberOfEntries - 1,
  (offset_of(entry[i]) + entry[i].EntryLength) mod 8 == 0
```

Each entry (except possibly the last) SHALL be padded so that the next entry starts on an 8-byte aligned offset relative to the table base.

### P2.4 Entry Reserved Fields Zero

```
∀ entry : EFI_CRYPTO_INDICATOR_ENTRY,
  entry.Reserved[0..5] == {0, 0, 0, 0, 0, 0}
```

### P2.5 No Entry Overflow

```
∀ entry[i] in table,
  offset_of(entry[i]) + entry[i].EntryLength <= table.Length
```

No entry SHALL extend beyond the declared table Length.

### P2.6 Non-Zero Entry Length

```
∀ entry : EFI_CRYPTO_INDICATOR_ENTRY,
  entry.EntryLength > 0
```

Prevents infinite loops during iteration.

---

## 3. Memory Type Properties

### P3.1 ACPI-Supported Memory Type

```
If AcpiSupported(platform):
  MemoryType(table_address) == EfiAcpiReclaimMemory
```

When ACPI is supported, the ECIT SHALL reside in EfiAcpiReclaimMemory to survive ExitBootServices.

### P3.2 Non-ACPI Memory Type

```
If ¬AcpiSupported(platform):
  MemoryType(table_address) == EfiBootServicesData
```

### P3.3 Configuration Table and ACPI Table Identity

```
If AcpiSupported(platform):
  let cfg_ptr = GetConfigurationTable(EFI_CRYPTO_INDICATOR_TABLE_GUID),
  let acpi_ptr = FindAcpiTable("ECIT"),
  cfg_ptr == acpi_ptr
```

The EFI_CONFIGURATION_TABLE pointer SHALL reference the exact same memory as the ACPI table. They SHALL NOT be independent copies.

---

## 4. Publishing Properties

### P4.1 Configuration Table Installation

```
∀ platform with SecureBoot,
  ∃ entry in SystemTable.ConfigurationTable where entry.VendorGuid == EFI_CRYPTO_INDICATOR_TABLE_GUID
```

The ECIT SHALL be published as an EFI Configuration Table on any Secure Boot capable platform.

### P4.2 ACPI Table Installation (Conditional)

```
If AcpiSupported(platform):
  ∃ acpi_table in RSDT/XSDT where acpi_table.Signature == "ECIT"
```

### P4.3 Dual-Publish Consistency

```
If AcpiSupported(platform):
  ConfigurationTable[ECIT_GUID].pointer == AcpiTable["ECIT"].pointer
  ∧ content(ConfigurationTable[ECIT_GUID]) == content(AcpiTable["ECIT"])
```

---

## 5. Required Feature Entry Properties (Secure Boot Systems)

### P5.1 Mandatory Entry Presence

```
If SecureBootSupported(platform):
  ∃ entry in table.Entries : entry.FeatureIdentifier == EFI_ECIT_FEATURE_IMAGE_VERIFICATION_GUID
  ∧ ∃ entry in table.Entries : entry.FeatureIdentifier == EFI_ECIT_FEATURE_SECURE_BOOT_AUTHORIZATION_GUID
  ∧ ∃ entry in table.Entries : entry.FeatureIdentifier == EFI_ECIT_FEATURE_SECURE_BOOT_SERVICING_AUTHORIZATION_GUID
  ∧ ∃ entry in table.Entries : entry.FeatureIdentifier == EFI_ECIT_FEATURE_IMAGE_REVOCATION_GUID
  ∧ ∃ entry in table.Entries : entry.FeatureIdentifier == EFI_ECIT_FEATURE_AUTHENTICATED_VARIABLE_GUID
```

All five Secure Boot feature entries are REQUIRED.

### P5.2 Non-Empty Entry Data

```
∀ required_entry in {ImageVerification, AuthenticatedVariable}:
  entry.EntryLength > sizeof(EFI_CRYPTO_INDICATOR_ENTRY)
  ∧ EntryData contains at least one valid OID string (non-empty, null-terminated)

∀ required_entry in {SecureBootAuthorization, ImageRevocation, ServicingAuthorization}:
  entry.EntryLength > sizeof(EFI_CRYPTO_INDICATOR_ENTRY)
  ∧ EntryData contains at least one valid EFI_GUID
```

Required entries SHALL contain at least one algorithm/type declaration.

---

## 6. Entry Data Format Properties

### P6.1 OID String Well-Formedness (Image Verification, Authenticated Variable)

```
∀ entry with FeatureIdentifier ∈ {IMAGE_VERIFICATION_GUID, AUTHENTICATED_VARIABLE_GUID}:
  let data = entry.EntryData,
  let data_size = entry.EntryLength - sizeof(EFI_CRYPTO_INDICATOR_ENTRY),
  data[data_size - 1] == 0x00  // null-terminated
  ∧ ∀ oid in split(data, ','):
      oid matches regex "[0-9]+(\.[0-9]+)+"  // valid dotted-decimal OID
```

### P6.2 OID CSV Non-Empty

```
∀ entry with OID-based EntryData:
  strlen(EntryData) > 0
  ∧ no empty elements between commas (no ",," substring)
```

### P6.3 GUID Array Well-Formedness (Authorization, Revocation)

```
∀ entry with FeatureIdentifier ∈ {SECURE_BOOT_AUTHORIZATION_GUID, IMAGE_REVOCATION_GUID, SERVICING_AUTHORIZATION_GUID}:
  let data_size = entry.EntryLength - sizeof(EFI_CRYPTO_INDICATOR_ENTRY),
  data_size mod sizeof(EFI_GUID) == 0
  ∧ data_size >= sizeof(EFI_GUID)
```

The GUID array data SHALL be an exact multiple of 16 bytes (sizeof(EFI_GUID)).

### P6.4 No Null GUIDs in Arrays

```
∀ guid in GUID_array_entries:
  guid != {00000000-0000-0000-0000-000000000000}
```

---

## 7. Iteration Safety Properties

### P7.1 Forward Progress (Termination)

```
∀ iteration over entries:
  let offset = 0, count = 0,
  while offset < (table.Length - header_size) ∧ count < NumberOfEntries:
    entry = entry_at(offset)
    offset += entry.EntryLength
    count += 1
  // Terminates because P2.6 guarantees EntryLength > 0
```

### P7.2 No Overlapping Entries

```
∀ i, j where i ≠ j:
  [offset(entry[i]), offset(entry[i]) + entry[i].EntryLength) ∩
  [offset(entry[j]), offset(entry[j]) + entry[j].EntryLength) == ∅
```

### P7.3 Contiguous Layout

```
offset(entry[0]) == sizeof(table_header)
∀ i in 1..NumberOfEntries-1:
  offset(entry[i]) == offset(entry[i-1]) + entry[i-1].EntryLength
```

Entries SHALL be laid out contiguously without gaps (padding is accounted for within EntryLength).

---

## 8. Consistency Properties (Cross-Module)

### P8.1 Image Verification OIDs Reflect Actual Crypto Capability

```
∀ oid in ECIT.ImageVerification.SupportedAlgorithmOids:
  CryptoLibrary.CanVerifySignature(oid) == TRUE
```

Every OID declared in the Image Verification entry SHALL correspond to an algorithm actually implemented and enabled in the linked crypto library.

### P8.2 Authorization Types Reflect Actual DB Processing

```
∀ guid in ECIT.SecureBootAuthorization.SignatureListSupportedTypes:
  ImageVerificationLib.CanProcessSignatureType(guid) == TRUE
```

### P8.3 Revocation Types Reflect Actual DBX Processing

```
∀ guid in ECIT.ImageRevocation.SignatureListSupportedTypes:
  ImageVerificationLib.CanProcessRevocationType(guid) == TRUE
```

### P8.4 Authenticated Variable OIDs Reflect Actual Auth Var Processing

```
∀ oid in ECIT.AuthenticatedVariable.SupportedAlgorithmOids:
  AuthVariableLib.CanVerifyPayload(oid) == TRUE
```

---

## 9. Immutability and Integrity Properties

### P9.1 Table Immutability Post-Installation

```
∀ t > t_install:
  content(table, t) == content(table, t_install)
```

Once installed, the ECIT table content SHALL NOT be modified. The table is a static declaration of capabilities at build/boot time.

### P9.2 Checksum Validity at All Access Points

```
∀ t where table is accessible:
  checksum_valid(table, t) == TRUE
```

Any consumer reading the table SHALL observe a valid checksum (this is a consequence of P9.1 + P1.4).

---

## 10. Security Properties

### P10.1 No Under-Declaration (Soundness)

```
∀ feature F, ∀ algorithm A:
  If Firmware.Supports(F, A) ∧ A is UEFI-standard:
    A ∈ ECIT.Feature(F).DeclaredAlgorithms
```

The ECIT SHALL NOT omit algorithms that the firmware actually supports (under-declaration may cause interoperability failures).

### P10.2 No Over-Declaration (Completeness)

```
∀ feature F, ∀ algorithm A:
  If A ∈ ECIT.Feature(F).DeclaredAlgorithms:
    Firmware.Supports(F, A) == TRUE
```

The ECIT SHALL NOT declare algorithms that the firmware does not actually support (over-declaration causes security failures when a consumer selects an unsupported algorithm).

---

## 11. Feature Identifier Uniqueness

### P11.1 No Duplicate Feature Entries (Standard Features)

```
∀ standard_guid ∈ {IMAGE_VERIFICATION, SECURE_BOOT_AUTHORIZATION, SERVICING_AUTHORIZATION, IMAGE_REVOCATION, AUTHENTICATED_VARIABLE}:
  |{entry ∈ table.Entries : entry.FeatureIdentifier == standard_guid}| <= 1
```

Each standard feature GUID SHALL appear at most once in the table.

---

## 12. ACPI SDT Header Field Properties

### P12.1 OemId Format

```
table.OemId ∈ printable ASCII characters ∪ {space}
|table.OemId| == 6
```

### P12.2 OemTableId Format

```
table.OemTableId ∈ printable ASCII characters ∪ {space, null}
|table.OemTableId| == 8
```

---

## 13. TCG Measurement Properties

### P13.1 ECIT Table Measured to TPM PCR1

```
If TpmPresent(platform):
  ∃ measurement M in TPM_EventLog where
    M.PCRIndex == 1
    ∧ M.EventType == EV_EFI_HANDOFF_TABLES2
    ∧ M.EventData contains EFI_CRYPTO_INDICATOR_TABLE_GUID
    ∧ M.DigestValue == Hash(table content)
```

When a TPM is present, the ECIT table content SHALL be measured (extended) into PCR[1] with EventType = EV_EFI_HANDOFF_TABLES2, so that remote attestation can verify the declared cryptographic capabilities.

### P13.2 Measurement Occurs After Table Finalization

```
∀ t_measure where Measure(table, PCR1) occurs at t_measure:
  t_measure >= t_install
  ∧ content(table, t_measure) == content(table, t_install)
```

The measurement SHALL occur after the table is fully constructed and installed (i.e., checksum valid, all entries populated), ensuring the measured value matches the published table.

### P13.3 Measurement Data Matches Published Table

```
If TpmPresent(platform):
  let measured_hash = EventLog.Entry(PCR1, EV_EFI_HANDOFF_TABLES2, ECIT_GUID).Digest,
  measured_hash == Hash(InstallConfigurationTable.TableData, 0, table.Length)
```

The digest extended into PCR[1] SHALL be computed over the exact bytes of the ECIT table (from offset 0 to Header.Length), ensuring consistency between the published table and the TPM measurement.

---

## Summary of Property Categories

| Category | Properties | Purpose |
|----------|-----------|---------|
| Structural | P1.1–P1.5, P2.1–P2.6 | Table/entry binary layout correctness |
| Memory | P3.1–P3.3 | Memory type compliance per ACPI support |
| Publishing | P4.1–P4.3 | Correct installation as ConfigTable + ACPI |
| Mandatory | P5.1–P5.2 | Required entries for Secure Boot |
| Data Format | P6.1–P6.4 | Entry data payload well-formedness |
| Iteration | P7.1–P7.3 | Safe traversal without crash or hang |
| Consistency | P8.1–P8.4 | Declared capabilities match implementation |
| Integrity | P9.1–P9.2 | Immutability and checksum maintenance |
| Security | P10.1–P10.2 | Soundness and completeness |
| Uniqueness | P11.1 | No duplicate standard feature entries |
| ACPI Header | P12.1–P12.2 | OEM identification fields |
| TCG Measurement | P13.1–P13.3 | TPM PCR1 measurement correctness |
