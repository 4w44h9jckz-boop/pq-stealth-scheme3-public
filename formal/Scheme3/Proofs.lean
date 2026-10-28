import Scheme3.Protocol

set_option autoImplicit false

namespace Scheme3

variable {Point : Type}

@[simp] theorem result_bind_ok {α β : Type} (a : α) (f : α → Except Error β) :
    ((Except.ok a : Except Error α) >>= f) = f a := rfl

@[simp] theorem result_bind_error {α β : Type} (e : Error) (f : α → Except Error β) :
    ((Except.error e : Except Error α) >>= f) = Except.error e := rfl

@[simp] theorem result_map_ok {α β : Type} (a : α) (f : α → β) :
    f <$> (Except.ok a : Except Error α) = Except.ok (f a) := rfl

@[simp] theorem result_map_error {α β : Type} (e : Error) (f : α → β) :
    f <$> (Except.error e : Except Error α) = Except.error e := rfl

@[simp] theorem result_pure {α : Type} (a : α) :
    (pure a : Except Error α) = Except.ok a := rfl

@[simp] theorem result_throw {α : Type} (e : Error) :
    (throw e : Except Error α) = Except.error e := rfl

theorem scalar_zero_rejected : scalar? 0 = none := by simp [scalar?]
theorem scalar_order_rejected : scalar? order = none := by simp [scalar?]
theorem scalar_max_accepted : ∃ s, scalar? (order - 1) = some s := by
  simp [scalar?, order]

theorem firstScalar_mem (bs : List Secret) (s : Scalar)
    (h : firstScalar bs = some s) :
    ∃ b ∈ bs, scalarOf b = some s := by
  induction bs with
  | nil => simp [firstScalar] at h
  | cons b rest ih =>
    cases hs : scalarOf b with
    | none =>
      have hr : firstScalar rest = some s := by simpa [firstScalar, hs] using h
      obtain ⟨b', hm, he⟩ := ih hr
      exact ⟨b', List.mem_cons_of_mem b hm, he⟩
    | some t =>
      have ht : t = s := Option.some.inj (by simpa [firstScalar, hs] using h)
      subst t
      exact ⟨b, by simp, hs⟩

/-- Success comes from one of the 257 enumerated attempts, all within the bound. -/
theorem reduction_bounded (p : Primitives Point) (base : Secret) (s : Scalar)
    (h : reduceToScalar p base = some s) :
    ∃ counter, counter < 257 ∧ scalarOf (offsetCandidate p base counter) = some s := by
  obtain ⟨b, hm, he⟩ := firstScalar_mem _ _ h
  obtain ⟨counter, hc, hb⟩ := List.mem_map.mp hm
  subst b
  exact ⟨counter, List.mem_range.mp hc, he⟩

theorem initial_candidate (p : Primitives Point) (base : Secret) :
    offsetCandidate p base 0 = base := by simp [offsetCandidate]

theorem last_candidate (p : Primitives Point) (base : Secret) :
    offsetCandidate p base 256 =
      p.sha256 (dsOffset ++ base.data ++ [(0 : UInt8)]) := by
  simp [offsetCandidate]

theorem no_scalar_search_exhausted :
    firstScalar ([] : List Secret) = none := rfl

theorem all_rejected_exhausts (bs : List Secret)
    (h : ∀ b ∈ bs, scalarOf b = none) : firstScalar bs = none := by
  induction bs with
  | nil => rfl
  | cons b rest ih =>
    have hb := h b (by simp)
    have hr : ∀ c ∈ rest, scalarOf c = none := by
      intro c hc
      exact h c (List.mem_cons_of_mem b hc)
    simp [firstScalar, hb, ih hr]

theorem delegation_covers_boundary (s : Block 32) (viewing : Block 32)
    (seed : KemSeed) (safe : DelegationSafe s (viewing.data ++ seed.data))
    (i : Nat) (hi : i < 65) :
    ((viewing.data ++ seed.data).drop i).take 32 ≠ s.data :=
  safe ⟨i, hi⟩

theorem delegated_length (v : Block 32) (seed : KemSeed) :
    (v.data ++ seed.data).length = 96 := by simp [v.size, seed.size]

theorem delegation_window_count : 96 - 32 + 1 = (65 : Nat) := rfl

theorem keygen_rejects_delegation (p : Primitives Point) (input : KeygenInput)
    (h : ¬ DelegationSafe input.spending (input.viewing.data ++ input.kemSeed.data)) :
    keygenFields p input = .error .spendingKeyDelegated := by
  simp [keygenFields, h]

theorem keygen_length_rejected (p : Primitives Point) (bs : Bytes)
    (h : bs.length ≠ 128) : keygen p bs = .error .malformed := by
  simp [keygen, parseKeygen, h, require]

theorem announce_length_rejected (p : Primitives Point) (meta : Meta Point) (bs : Bytes)
    (h : bs.length ≠ 64) : announce p meta bs = .error .malformed := by
  simp [announce, parseAnnounce, h, require]

theorem meta_wire_length (p : Primitives Point) (meta : Meta Point) :
    (encodeMeta p meta).length = 1250 := by
  simp [encodeMeta, (p.encodePoint meta.spending).size,
    (p.encodePoint meta.viewing).size, meta.ek.size]

theorem metadata_wire_length (ann : Announcement Point) :
    (encodeMetadata ann).length = 1089 := by
  simp [encodeMetadata, ann.ct.size]

theorem announcement_wire_length (p : Primitives Point) (ann : Announcement Point) :
    (encodeEvent p ann).ephemeralPubKey.length +
      (encodeEvent p ann).metadata.length = 1122 := by
  simp [encodeEvent, encodeMetadata, (p.encodePoint ann.epk).size, ann.ct.size]

theorem metadata_tag_first (ann : Announcement Point) :
    (encodeMetadata ann).head? = some ann.tag := rfl

theorem parse_meta_wrong_length (p : Primitives Point) (bs : Bytes)
    (h : bs.length ≠ 1250) : parseMeta p bs = none := by
  simp [parseMeta, h]

theorem parse_announcement_wrong_length (p : Primitives Point)
    (address : Address) (epk metadata : Bytes)
    (h : epk.length ≠ 33 ∨ metadata.length ≠ 1089) :
    parseAnnouncement p address epk metadata = none := by
  simp [parseAnnouncement, h]

theorem parse_point_roundtrip (p : Primitives Point) (laws : EcLaws p) (x : Point) :
    parsePoint p (p.encodePoint x).data = some x := by
  simp [parsePoint, block_roundtrip, laws.compressed, laws.decode_encode]

theorem parse_announcement_roundtrip (p : Primitives Point) (laws : EcLaws p)
    (ann : Announcement Point) :
    parseAnnouncement p ann.address (p.encodePoint ann.epk).data
      (encodeMetadata ann) = some ann := by
  cases ann with
  | mk epk ct tag address =>
    simp [parseAnnouncement, encodeMetadata, (p.encodePoint epk).size,
      ct.size, parse_point_roundtrip p laws, block_roundtrip]

theorem bind_generated (p : Primitives Point) [DecidableEq Point]
    (spending viewing : Scalar) (seed : KemSeed) :
    bind p ⟨viewing, seed⟩ (metaFor p spending viewing seed) =
      .ok ⟨metaFor p spending viewing seed, ⟨viewing, seed⟩⟩ := by
  simp [bind, metaFor]

/-- Binding authenticates the public ek, not every byte of (d,z). -/
theorem bind_accepts_same_ek (p : Primitives Point) [DecidableEq Point]
    (spending viewing : Scalar) (original replacement : KemSeed)
    (h : p.kemEk replacement = p.kemEk original) :
    bind p ⟨viewing, replacement⟩ (metaFor p spending viewing original) =
      .ok ⟨metaFor p spending viewing original, ⟨viewing, replacement⟩⟩ := by
  simp [bind, metaFor, h]

theorem match_complete (p : Primitives Point) (spending : Point)
    (ss : Secret) (tag : UInt8) (address : Address) (off : Scalar) (stealth : Point)
    (ht : viewTag p ss = tag) (ho : offset p ss = some off)
    (hp : p.addPoint spending off = some stealth) (ha : addressOf p stealth = address) :
    matchFromSecret p spending ss tag address = some ⟨address, ss⟩ := by
  simp [matchFromSecret, ht, ho, hp, ha]

theorem match_sound (p : Primitives Point) (spending : Point)
    (ss : Secret) (tag : UInt8) (address : Address) (m : MatchResult)
    (h : matchFromSecret p spending ss tag address = some m) :
    m = ⟨address, ss⟩ ∧ viewTag p ss = tag ∧
      ∃ off stealth, offset p ss = some off ∧
        p.addPoint spending off = some stealth ∧ addressOf p stealth = address := by
  unfold matchFromSecret at h
  split at h
  · rename_i ht
    cases ho : offset p ss with
    | none => simp [ho] at h
    | some off =>
      cases hp : p.addPoint spending off with
      | none => simp [ho, hp] at h
      | some stealth =>
        have h' : (if addressOf p stealth = address then some ⟨address, ss⟩ else none) =
            some m := by simpa [ho, hp] using h
        split at h'
        · rename_i ha
          exact ⟨(Option.some.inj h').symm, ht, off, stealth, rfl, hp, ha⟩
        · simp at h'
  · simp at h

theorem scan_sound (p : Primitives Point) (scanner : Scanner Point)
    (ann : Announcement Point) (m : MatchResult) (h : scan p scanner ann = some m) :
    m.address = ann.address ∧ m.secret = receiverSecret p scanner ann ∧
      Accepts p scanner ann := by
  obtain ⟨hm, ht, rest⟩ := match_sound p _ _ _ _ _ h
  subst m
  exact ⟨rfl, rfl, ht, rest⟩

theorem scan_complete (p : Primitives Point) (scanner : Scanner Point)
    (ann : Announcement Point) (h : Accepts p scanner ann) :
    scan p scanner ann = some ⟨ann.address, receiverSecret p scanner ann⟩ := by
  obtain ⟨ht, off, stealth, ho, hp, ha⟩ := h
  exact match_complete p _ _ _ _ off stealth ht ho hp ha

theorem scan_accepts_iff (p : Primitives Point) (scanner : Scanner Point)
    (ann : Announcement Point) :
    (∃ m, scan p scanner ann = some m) ↔ Accepts p scanner ann := by
  constructor
  · rintro ⟨m, h⟩
    exact (scan_sound p scanner ann m h).2.2
  · intro h
    exact ⟨_, scan_complete p scanner ann h⟩

theorem tag_mismatch_skips (p : Primitives Point) (spending : Point)
    (ss : Secret) (tag : UInt8) (address : Address) (h : viewTag p ss ≠ tag) :
    matchFromSecret p spending ss tag address = none := by
  simp [matchFromSecret, h]

theorem address_mismatch_skips (p : Primitives Point) (spending : Point)
    (ss : Secret) (tag : UInt8) (address : Address) (off : Scalar) (stealth : Point)
    (ho : offset p ss = some off) (hp : p.addPoint spending off = some stealth)
    (ha : addressOf p stealth ≠ address) :
    matchFromSecret p spending ss tag address = none := by
  simp [matchFromSecret, ho, hp, ha]

theorem foreign_scheme_skips (p : Primitives Point) (registered : List Nat)
    (scanner : Scanner Point) (event : WireEvent) (h : event.schemeId ≠ 3) :
    scanEvent p registered scanner event = none := by
  simp [scanEvent, h]

theorem unregistered_scheme_skips (p : Primitives Point) (registered : List Nat)
    (scanner : Scanner Point) (event : WireEvent) (h : event.schemeId ∉ registered) :
    scanEvent p registered scanner event = none := by
  simp [scanEvent, h]

theorem receiver_agreement (p : Primitives Point) (laws : EcLaws p)
    (spending viewing esk : Scalar) (seed : KemSeed) (ct : Ciphertext) (pq : Secret)
    (tag : UInt8) (address : Address) (hkem : KemAgrees p seed ct pq) :
    receiverSecret p ⟨metaFor p spending viewing seed, ⟨viewing, seed⟩⟩
      ⟨p.public esk, ct, tag, address⟩ =
      combine p (p.ecdh esk (p.public viewing)) pq (p.public esk) ct
        (p.public viewing) (p.kemEk seed) := by
  unfold receiverSecret metaFor
  rw [laws.ecdh_symmetric viewing esk, hkem]

/-- Conditional end-to-end functional correctness; no perfect KEM-correctness axiom. -/
theorem honest_payment (p : Primitives Point) (laws : EcLaws p)
    (spending viewing esk : Scalar) (seed : KemSeed) (message : Secret)
    (ct : Ciphertext) (pq : Secret) (off sk : Scalar)
    (henc : p.encaps (p.kemEk seed) message = some (ct, pq))
    (hkem : KemAgrees p seed ct pq)
    (hoff : offset p (combine p (p.ecdh esk (p.public viewing)) pq
      (p.public esk) ct (p.public viewing) (p.kemEk seed)) = some off)
    (hadd : addScalars spending off = some sk) :
    let meta := metaFor p spending viewing seed
    let ss := combine p (p.ecdh esk (p.public viewing)) pq
      (p.public esk) ct (p.public viewing) (p.kemEk seed)
    let address := addressOf p (p.public sk)
    let ann : Announcement Point := ⟨p.public esk, ct, viewTag p ss, address⟩
    announceCore p meta esk message = .ok ann ∧
      scan p ⟨meta, ⟨viewing, seed⟩⟩ ann = some ⟨address, ss⟩ ∧
      spendKey p ⟨spending⟩ ⟨address, ss⟩ = .ok sk := by
  dsimp
  have hp : p.addPoint (p.public spending) off = some (p.public sk) := by
    rw [laws.add_public, hadd]
    rfl
  constructor
  · simp [announceCore, metaFor, require, henc, hoff, hp]
  constructor
  · unfold scan
    rw [receiver_agreement p laws spending viewing esk seed ct pq _ _ hkem]
    exact match_complete p _ _ _ _ off (p.public sk) rfl hoff hp rfl
  · simp [spendKey, require, hoff, hadd]

theorem zero_sum_rejected (a b : Scalar) (h : (a.val + b.val) % order = 0) :
    addScalars a b = none := by
  simp [addScalars, h, scalar?]

/-- Knowing both the one-time scalar and offset recovers the master scalar. -/
theorem master_recovery (a b : Scalar) :
    (((a.val + b.val) % order + order - b.val) % order) = a.val := by
  have ha := a.property
  have hb := b.property
  unfold order at *
  omega

theorem fresh_extension (seed : Block 64) (history : List (Block 64)) :
    FreshSeeds (seed :: history) ↔ seed ∉ history ∧ FreshSeeds history := by
  simp [FreshSeeds]

theorem drawIndex_advances (i used next : Nat)
    (h : drawIndex i = some (used, next)) :
    used = i ∧ next = i + 1 ∧ i < next ∧ next < 2 ^ 64 := by
  unfold drawIndex at h
  split at h
  · rename_i bound
    have hp := Option.some.inj h
    cases hp
    omega
  · simp at h

theorem drawIndex_exhausted :
    drawIndex (2 ^ 64 - 1) = none := by
  simp [drawIndex]

end Scheme3
