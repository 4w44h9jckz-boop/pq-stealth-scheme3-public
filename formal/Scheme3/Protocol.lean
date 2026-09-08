import Scheme3.Base

set_option autoImplicit false

namespace Scheme3

variable {Point : Type}

inductive Error where
  | malformed
  | noValidScalar
  | spendingKeyDelegated
  | seedRejected
  | kem
  | trackingKeyMismatch
  | masterKeyMismatch
  deriving DecidableEq, Repr

def require {α : Type} (err : Error) : Option α → Except Error α
  | some a => .ok a
  | none => .error err

structure Meta (Point : Type) where
  spending : Point
  viewing : Point
  ek : EncKey

/-- Abstracts the spending component actually used by Rust's spend_key_from. -/
structure Master where
  spending : Scalar

structure Tracking where
  viewing : Scalar
  kemSeed : KemSeed

structure Keys (Point : Type) where
  meta : Meta Point
  master : Master
  tracking : Tracking

structure Announcement (Point : Type) where
  epk : Point
  ct : Ciphertext
  tag : UInt8
  address : Address

structure MatchResult where
  address : Address
  secret : Secret
  deriving DecidableEq

structure Scanner (Point : Type) where
  meta : Meta Point
  tracking : Tracking

structure KeygenInput where
  spending : Block 32
  viewing : Block 32
  kemSeed : KemSeed

structure AnnounceInput where
  ephemeral : Block 32
  message : Secret

def parseKeygen (bs : Bytes) : Option KeygenInput := do
  if bs.length ≠ 128 then none else do
    let spending ← block? 32 (bs.take 32)
    let viewing ← block? 32 ((bs.drop 32).take 32)
    let kemSeed ← block? 64 (bs.drop 64)
    pure ⟨spending, viewing, kemSeed⟩

def parseAnnounce (bs : Bytes) : Option AnnounceInput := do
  if bs.length ≠ 64 then none else do
    let ephemeral ← block? 32 (bs.take 32)
    let message ← block? 32 (bs.drop 32)
    pure ⟨ephemeral, message⟩

def metaFor (p : Primitives Point) (spending viewing : Scalar)
    (kemSeed : KemSeed) : Meta Point :=
  ⟨p.public spending, p.public viewing, p.kemEk kemSeed⟩

def keygenFields (p : Primitives Point) (input : KeygenInput) :
    Except Error (Keys Point) := do
  if ¬ DelegationSafe input.spending (input.viewing.data ++ input.kemSeed.data) then
    throw .spendingKeyDelegated
  let spending ← require .noValidScalar (scalarOf input.spending)
  let viewing ← require .noValidScalar (scalarOf input.viewing)
  pure ⟨metaFor p spending viewing input.kemSeed,
    ⟨spending⟩, ⟨viewing, input.kemSeed⟩⟩

def keygen (p : Primitives Point) (bs : Bytes) : Except Error (Keys Point) := do
  let input ← require .malformed (parseKeygen bs)
  keygenFields p input

def encodeMeta (p : Primitives Point) (meta : Meta Point) : Bytes :=
  (p.encodePoint meta.spending).data ++ (p.encodePoint meta.viewing).data ++ meta.ek.data

def parseMeta (p : Primitives Point) (bs : Bytes) : Option (Meta Point) := do
  if bs.length ≠ 1250 then none else do
    let spending ← parsePoint p (bs.take 33)
    let viewing ← parsePoint p ((bs.drop 33).take 33)
    let ek ← block? 1184 (bs.drop 66)
    pure ⟨spending, viewing, ek⟩

def bind (p : Primitives Point) [DecidableEq Point]
    (tracking : Tracking) (meta : Meta Point) : Except Error (Scanner Point) :=
  if p.public tracking.viewing = meta.viewing ∧ p.kemEk tracking.kemSeed = meta.ek
  then .ok ⟨meta, tracking⟩ else .error .trackingKeyMismatch

/-- Well-typed sender core. Raw seed/scalar errors are handled by announce. -/
def announceCore (p : Primitives Point) (meta : Meta Point)
    (esk : Scalar) (message : Secret) : Except Error (Announcement Point) := do
  let epk := p.public esk
  let ec := p.ecdh esk meta.viewing
  let (ct, pq) ← require .kem (p.encaps meta.ek message)
  let ss := combine p ec pq epk ct meta.viewing meta.ek
  let off ← require .noValidScalar (offset p ss)
  let stealth ← require .malformed (p.addPoint meta.spending off)
  pure ⟨epk, ct, viewTag p ss, addressOf p stealth⟩

def announce (p : Primitives Point) (meta : Meta Point)
    (bs : Bytes) : Except Error (Announcement Point) := do
  let input ← require .malformed (parseAnnounce bs)
  let esk ← require .seedRejected (scalarOf input.ephemeral)
  announceCore p meta esk input.message

def encodeMetadata (ann : Announcement Point) : Bytes :=
  ann.tag :: ann.ct.data

structure WireEvent where
  schemeId : Nat
  address : Address
  ephemeralPubKey : Bytes
  metadata : Bytes

def encodeEvent (p : Primitives Point) (ann : Announcement Point) : WireEvent :=
  ⟨3, ann.address, (p.encodePoint ann.epk).data, encodeMetadata ann⟩

def parseAnnouncement (p : Primitives Point)
    (address : Address) (epk metadata : Bytes) : Option (Announcement Point) := do
  if epk.length ≠ 33 ∨ metadata.length ≠ 1089 then none else do
    let point ← parsePoint p epk
    match metadata with
    | [] => none
    | tag :: rest =>
      let ct ← block? 1088 rest
      pure ⟨point, ct, tag, address⟩

def receiverSecret (p : Primitives Point) (scanner : Scanner Point)
    (ann : Announcement Point) : Secret :=
  combine p (p.ecdh scanner.tracking.viewing ann.epk)
    (p.decaps scanner.tracking.kemSeed ann.ct)
    ann.epk ann.ct scanner.meta.viewing scanner.meta.ek

def matchFromSecret (p : Primitives Point) (spending : Point)
    (ss : Secret) (tag : UInt8) (address : Address) : Option MatchResult :=
  if viewTag p ss = tag then
    match offset p ss with
    | none => none
    | some off =>
      match p.addPoint spending off with
      | none => none
      | some stealth =>
        if addressOf p stealth = address then some ⟨address, ss⟩ else none
  else none

def scan (p : Primitives Point) (scanner : Scanner Point)
    (ann : Announcement Point) : Option MatchResult :=
  matchFromSecret p scanner.meta.spending (receiverSecret p scanner ann) ann.tag ann.address

/-- Dispatcher obligation absent from the Rust StealthScheme trait's typed scan. -/
def scanEvent (p : Primitives Point) (registered : List Nat)
    (scanner : Scanner Point) (event : WireEvent) : Option MatchResult :=
  if event.schemeId = 3 ∧ event.schemeId ∈ registered then do
    let ann ← parseAnnouncement p event.address event.ephemeralPubKey event.metadata
    scan p scanner ann
  else none

def spendKey (p : Primitives Point) (master : Master)
    (matched : MatchResult) : Except Error Scalar := do
  let off ← require .noValidScalar (offset p matched.secret)
  let sk ← require .noValidScalar (addScalars master.spending off)
  if addressOf p (p.public sk) = matched.address then
    pure sk
  else throw .masterKeyMismatch

/-- Does not assert that the event was funded or came from honest encapsulation. -/
def Accepts (p : Primitives Point) (scanner : Scanner Point)
    (ann : Announcement Point) : Prop :=
  let ss := receiverSecret p scanner ann
  viewTag p ss = ann.tag ∧
    ∃ off stealth, offset p ss = some off ∧
      p.addPoint scanner.meta.spending off = some stealth ∧
      addressOf p stealth = ann.address

/-- Per-instance agreement: ML-KEM correctness is not assumed perfect for all seeds. -/
def KemAgrees (p : Primitives Point) (seed : KemSeed)
    (ct : Ciphertext) (pq : Secret) : Prop :=
  p.decaps seed ct = pq

/-- Global wallet obligation: the raw deterministic sender does not enforce this. -/
def FreshSeeds (history : List (Block 64)) : Prop := history.Nodup

/-- An implementation-level counter model; uniqueness of KDF outputs is not implied. -/
def drawIndex (i : Nat) : Option (Nat × Nat) :=
  if i < 2 ^ 64 - 1 then some (i, i + 1) else none

end Scheme3
