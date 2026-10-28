import Std

/-!
# Scheme 3: concrete framing and abstract primitive boundary

Source: 4w44h9jckz-boop/pq-stealth-scheme3-public
Commit: 5fe8d0fd928155a56c74810ad9026807e548818b

Byte layouts, domain separators, scalar range, modular scalar addition, the
257-attempt search and delegation windows are concrete. Hashes, secp256k1
points and ML-KEM operations are supplied through Primitives. No security
assumptions, primitive implementations or correctness axioms are installed.
-/

set_option autoImplicit false

namespace Scheme3

abbrev Bytes := List UInt8

structure Block (n : Nat) where
  data : Bytes
  size : data.length = n
  deriving DecidableEq, Repr

def block? (n : Nat) (bs : Bytes) : Option (Block n) :=
  if h : bs.length = n then some ⟨bs, h⟩ else none

theorem block_roundtrip {n : Nat} (b : Block n) :
    block? n b.data = some b := by
  cases b with
  | mk data size => simp [block?, size]

def ascii (s : String) : Bytes := s.toUTF8.toList

def dsOffset : Bytes := ascii "pq-stealth/offset/v1"
def dsViewTag : Bytes := ascii "pq-stealth/view-tag/v1"
def dsHybrid : Bytes := ascii "pq-stealth/hybrid-payment/v1"

def order : Nat :=
  0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

abbrev Scalar := {x : Nat // 0 < x ∧ x < order}
abbrev Address := Block 20
abbrev Secret := Block 32
abbrev KemSeed := Block 64
abbrev EncKey := Block 1184
abbrev Ciphertext := Block 1088

def scalar? (x : Nat) : Option Scalar :=
  if h : 0 < x ∧ x < order then some ⟨x, h⟩ else none

def u256be (b : Block 32) : Nat :=
  b.data.foldl (fun acc byte => acc * 256 + byte.toNat) 0

def scalarOf (b : Block 32) : Option Scalar := scalar? (u256be b)

def scalarBytes (s : Scalar) : Block 32 :=
  ⟨List.ofFn (fun i : Fin 32 =>
    UInt8.ofNat (s.val / 256 ^ (31 - i.val) % 256)), by simp⟩

def addScalars (a b : Scalar) : Option Scalar :=
  scalar? ((a.val + b.val) % order)

/-- The raw-byte coincidence guard. This is not a cryptographic secrecy claim. -/
def DelegationSafe (spending : Block 32) (delegated : Bytes) : Prop :=
  ∀ i : Fin 65, (delegated.drop i.val).take 32 ≠ spending.data

instance (spending : Block 32) (delegated : Bytes) :
    Decidable (DelegationSafe spending delegated) :=
  inferInstanceAs (Decidable (∀ i : Fin 65,
    (delegated.drop i.val).take 32 ≠ spending.data))

structure Primitives (Point : Type) where
  sha256 : Bytes → Secret
  sha3_256 : Bytes → Secret
  keccak256 : Bytes → Secret
  encodePoint : Point → Block 33
  /-- Must reject off-curve points and noncanonical coordinates. Prefix checked separately. -/
  decodePoint : Block 33 → Option Point
  /-- Uncompressed x || y, without SEC1's 0x04 prefix. -/
  xy : Point → Block 64
  public : Scalar → Point
  /-- Big-endian x-coordinate alone. -/
  ecdh : Scalar → Point → Secret
  /-- P + offset*G; none at infinity. -/
  addPoint : Point → Scalar → Option Point
  /-- KeyGen_internal(d,z); input seed is retained as dk. -/
  kemEk : KemSeed → EncKey
  /-- Encaps_internal(ek,m); none for a rejected encapsulation key. -/
  encaps : EncKey → Secret → Option (Ciphertext × Secret)
  /-- Total on sized inputs, including implicit-rejection ciphertexts. -/
  decaps : KemSeed → Ciphertext → Secret

variable {Point : Type}

def sec1Prefix (b : Block 33) : Bool :=
  b.data.head? == some (2 : UInt8) || b.data.head? == some (3 : UInt8)

def parsePoint (p : Primitives Point) (bs : Bytes) : Option Point := do
  let b ← block? 33 bs
  if sec1Prefix b then p.decodePoint b else none

def addressOf (p : Primitives Point) (point : Point) : Address :=
  ⟨(p.keccak256 (p.xy point).data).data.drop 12, by
    simp [(p.keccak256 (p.xy point).data).size]⟩

def hybridInput (p : Primitives Point) (ec pq : Secret)
    (epk : Point) (ct : Ciphertext) (viewing : Point) (ek : EncKey) : Bytes :=
  dsHybrid ++ ec.data ++ pq.data ++ (p.encodePoint epk).data ++
    ct.data ++ (p.encodePoint viewing).data ++ ek.data

def combine (p : Primitives Point) (ec pq : Secret)
    (epk : Point) (ct : Ciphertext) (viewing : Point) (ek : EncKey) : Secret :=
  p.sha3_256 (hybridInput p ec pq epk ct viewing ek)

def viewTag (p : Primitives Point) (ss : Secret) : UInt8 :=
  ((p.sha256 (dsViewTag ++ ss.data)).data.head?).getD 0

/-- Counter 256 is explicitly truncated to byte 0, matching Rust's cast. -/
def offsetCandidate (p : Primitives Point) (base : Secret) (counter : Nat) : Secret :=
  if counter = 0 then base
  else p.sha256 (dsOffset ++ base.data ++ [UInt8.ofNat counter])

def firstScalar : List Secret → Option Scalar
  | [] => none
  | b :: rest =>
    match scalarOf b with
    | some s => some s
    | none => firstScalar rest

def reduceToScalar (p : Primitives Point) (base : Secret) : Option Scalar :=
  firstScalar ((List.range 257).map (offsetCandidate p base))

def offset (p : Primitives Point) (ss : Secret) : Option Scalar :=
  reduceToScalar p (p.sha256 (dsOffset ++ ss.data))

/-- Backend algebra/codec obligations, passed to theorems as hypotheses. -/
structure EcLaws (p : Primitives Point) : Prop where
  decode_encode : ∀ x, p.decodePoint (p.encodePoint x) = some x
  compressed : ∀ x, sec1Prefix (p.encodePoint x) = true
  ecdh_symmetric : ∀ a b, p.ecdh a (p.public b) = p.ecdh b (p.public a)
  add_public : ∀ a b, p.addPoint (p.public a) b = (addScalars a b).map p.public

end Scheme3
