"use strict";

const crypto = require("crypto");
const { setGlobalOptions } = require("firebase-functions/v2");
const { onCall, HttpsError } = require("firebase-functions/v2/https");
const { initializeApp } = require("firebase-admin/app");
const { getAuth } = require("firebase-admin/auth");
const { FieldValue, getFirestore } = require("firebase-admin/firestore");

setGlobalOptions({ region: "us-central1", maxInstances: 10 });
initializeApp();

const db = getFirestore();
const auth = getAuth();
const BARS = "ABCDEFGHIJKLMNR";
// Keep requests available while the production reCAPTCHA Enterprise key is being verified.
const CALLABLE = { enforceAppCheck: false };

function fail(code, message) {
  throw new HttpsError(code, message);
}

function cleanText(value, max, field) {
  const text = String(value || "").trim();
  if (!text || text.length > max) fail("invalid-argument", `قيمة ${field} غير صحيحة.`);
  return text;
}

function cleanOptionalText(value, max, field) {
  const text = String(value || "").trim();
  if (text.length > max) fail("invalid-argument", `قيمة ${field} غير صحيحة.`);
  return text;
}

function validBuilding(id) {
  return typeof id === "string" && /^[A-NR][1-5]$/.test(id) && BARS.includes(id[0]);
}

function parseUnit(value) {
  const code = String(value || "").toUpperCase().replace(/[\s_-]/g, "");
  if (!/^[A-NR][1-5][0-6][1-6]$/.test(code) || !BARS.includes(code[0])) {
    fail("invalid-argument", "رقم الشقة غير صحيح.");
  }
  return { code, buildingId: code.slice(0, 2) };
}

function validPhone(value) {
  return !value || /^\+?[0-9\s()\-]{7,20}$/.test(value);
}

function normalizeCode(value) {
  return String(value || "").trim().toUpperCase().replace(/\s+/g, "");
}

function hashCode(code) {
  return crypto.createHash("sha256").update(normalizeCode(code)).digest("hex");
}

async function accountFromRequest(request, requireActive = true) {
  if (!request.auth) fail("unauthenticated", "سجّل الدخول أولًا.");
  const userRef = db.collection("users").doc(request.auth.uid);
  const snap = await userRef.get();
  if (!snap.exists) fail("permission-denied", "ملف الحساب غير موجود.");
  const profile = snap.data();
  if (requireActive && profile.active !== true) fail("permission-denied", "فعّل بريدك الإلكتروني أولًا.");
  return { uid: request.auth.uid, userRef, profile, admin: profile.role === "admin" };
}

async function buildingFromAccessCode(input) {
  const accessCode = normalizeCode(input);
  const match = accessCode.match(/^GIRAN-([A-NR][1-5])-[A-F0-9]{20}$/);
  if (!match || !validBuilding(match[1])) fail("invalid-argument", "كود تفعيل العمارة غير صحيح.");
  const buildingId = match[1];
  const [building, savedCode] = await Promise.all([
    db.collection("buildings").doc(buildingId).get(),
    db.collection("buildingAccessCodes").doc(buildingId).get(),
  ]);
  if (!building.exists || !savedCode.exists || savedCode.data().active !== true || savedCode.data().hash !== hashCode(accessCode)) {
    fail("permission-denied", "كود التفعيل غير صحيح أو تم تدويره.");
  }
  return buildingId;
}

exports.activateAccount = onCall(CALLABLE, async (request) => {
  const data = request.data || {};
  const name = cleanText(data.name, 100, "الاسم");
  const email = cleanText(data.email, 254, "البريد الإلكتروني").toLowerCase();
  const password = String(data.password || "");
  if (!/^\S+@\S+\.\S+$/.test(email) || password.length < 8 || data.privacyConsent !== true) {
    fail("invalid-argument", "البريد الإلكتروني أو كلمة المرور غير صحيحين.");
  }
  const buildingId = await buildingFromAccessCode(data.buildingCode);
  try {
    await auth.getUserByEmail(email);
    fail("already-exists", "هذا البريد مسجل بالفعل.");
  } catch (error) {
    if (error instanceof HttpsError) throw error;
    if (error.code !== "auth/user-not-found") throw error;
  }

  let user;
  try {
    user = await auth.createUser({ email, password, displayName: name });
    await db.collection("users").doc(user.uid).create({
      name,
      email,
      role: "resident",
      active: false,
      buildingIds: [buildingId],
      unitCodes: [],
      privacyConsentAt: FieldValue.serverTimestamp(),
      privacyPolicyVersion: "2026-10",
      createdAt: FieldValue.serverTimestamp(),
    });
    return { ok: true };
  } catch (error) {
    if (user) await auth.deleteUser(user.uid).catch(() => undefined);
    throw error;
  }
});

exports.confirmEmailVerification = onCall(CALLABLE, async (request) => {
  const account = await accountFromRequest(request, false);
  if (request.auth.token.email_verified !== true) fail("failed-precondition", "تحقق من البريد الإلكتروني أولًا.");
  await account.userRef.update({ active: true, activatedAt: FieldValue.serverTimestamp() });
  return { ok: true };
});

exports.addBuildingAccess = onCall(CALLABLE, async (request) => {
  const account = await accountFromRequest(request);
  const buildingId = await buildingFromAccessCode(request.data?.buildingCode);
  if (account.profile.buildingIds.includes(buildingId)) return { buildingId, alreadyAdded: true };
  if (account.profile.buildingIds.length >= 10) fail("resource-exhausted", "وصلت للحد الأقصى من العمارات المرتبطة بالحساب.");
  await account.userRef.update({ buildingIds: FieldValue.arrayUnion(buildingId) });
  return { buildingId, alreadyAdded: false };
});

exports.upsertMyUnit = onCall(CALLABLE, async (request) => {
  const account = await accountFromRequest(request);
  const data = request.data || {};
  const { code, buildingId } = parseUnit(data.unitCode);
  if (!account.admin && !account.profile.buildingIds.includes(buildingId)) {
    fail("permission-denied", "هذه العمارة غير مرتبطة بحسابك.");
  }
  const ownerName = cleanText(data.ownerName, 100, "الاسم");
  const primaryPhone = cleanText(data.primaryPhone, 20, "الهاتف الأساسي");
  const extraPhone = cleanOptionalText(data.extraPhone, 20, "الهاتف الإضافي");
  const emergencyName = cleanOptionalText(data.emergencyName, 100, "اسم جهة الطوارئ");
  const emergencyPhone = cleanOptionalText(data.emergencyPhone, 20, "هاتف الطوارئ");
  if (![primaryPhone, extraPhone, emergencyPhone].every(validPhone)) fail("invalid-argument", "أحد أرقام الهاتف غير صحيح.");

  const unitRef = db.collection("units").doc(code);
  await db.runTransaction(async (transaction) => {
    const unit = await transaction.get(unitRef);
    if (!unit.exists) fail("not-found", "الشقة غير موجودة.");
    const current = unit.data();
    if (current.buildingId !== buildingId) fail("failed-precondition", "بيانات الشقة غير متسقة.");
    if (!account.admin && current.ownerUid && current.ownerUid !== account.uid) {
      fail("already-exists", "هذه الشقة مرتبطة بمالك آخر.");
    }
    transaction.update(unitRef, {
      ownerUid: account.uid,
      ownerName,
      primaryPhone,
      extraPhone,
      emergencyName,
      emergencyPhone,
      updatedAt: FieldValue.serverTimestamp(),
    });
    transaction.update(account.userRef, { unitCodes: FieldValue.arrayUnion(code) });
  });
  return { code };
});

exports.provisionBuilding = onCall(CALLABLE, async (request) => {
  const account = await accountFromRequest(request);
  if (!account.admin) fail("permission-denied", "هذه العملية للأدمن فقط.");
  const bar = String(request.data?.bar || "").toUpperCase();
  const number = Number(request.data?.number);
  const perFloor = Number(request.data?.perFloor);
  const id = `${bar}${number}`;
  if (!validBuilding(id) || !Number.isInteger(number) || ![3, 4, 5, 6].includes(perFloor)) {
    fail("invalid-argument", "بيانات العمارة غير صحيحة.");
  }
  if ((await db.collection("buildings").doc(id).get()).exists) fail("already-exists", "هذه العمارة مجهزة بالفعل.");
  const batch = db.batch();
  batch.create(db.collection("buildings").doc(id), { bar, number, perFloor, createdAt: FieldValue.serverTimestamp() });
  for (let floor = 0; floor <= 6; floor += 1) {
    for (let position = 1; position <= perFloor; position += 1) {
      const code = `${id}${floor}${position}`;
      batch.create(db.collection("units").doc(code), {
        code, bar, buildingId: id, floor, position, apartment: `${floor}${position}`,
        ownerUid: "", ownerName: "", primaryPhone: "", extraPhone: "", emergencyName: "", emergencyPhone: "",
        createdAt: FieldValue.serverTimestamp(),
      });
    }
  }
  await batch.commit();
  return { buildingId: id };
});

exports.generateBuildingAccessCode = onCall(CALLABLE, async (request) => {
  const account = await accountFromRequest(request);
  if (!account.admin) fail("permission-denied", "هذه العملية للأدمن فقط.");
  const buildingId = String(request.data?.buildingId || "").toUpperCase();
  if (!validBuilding(buildingId) || !(await db.collection("buildings").doc(buildingId).get()).exists) {
    fail("not-found", "العمارة غير موجودة.");
  }
  const code = `GIRAN-${buildingId}-${crypto.randomBytes(10).toString("hex").toUpperCase()}`;
  await db.collection("buildingAccessCodes").doc(buildingId).set({
    buildingId,
    hash: hashCode(code),
    active: true,
    issuedBy: account.uid,
    issuedAt: FieldValue.serverTimestamp(),
    version: FieldValue.increment(1),
  }, { merge: true });
  return { code };
});
