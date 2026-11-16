package app.tgseed.patches.skvalex

import app.morphe.patcher.extensions.InstructionExtensions.addInstructions
import app.morphe.patcher.patch.PatchException
import app.morphe.patcher.patch.bytecodePatch
import app.tgseed.patches.shared.Constants.COMPATIBILITY_CALLRECORDER
import com.android.tools.smali.dexlib2.AccessFlags
import com.android.tools.smali.dexlib2.iface.ClassDef
import com.android.tools.smali.dexlib2.iface.Method
import com.android.tools.smali.dexlib2.iface.instruction.Instruction
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction
import com.android.tools.smali.dexlib2.iface.reference.MethodReference

/**
 * Makes the app permanently report a verified licence.
 *
 * How the licence works in this app (verified on 3.7.8, classes.dex + smali):
 *
 *   - One int field on the Application class holds the state: 0 = check pending, 1/2 = not
 *     licensed (trial or error), 3/4 = licensed. It is written by the native licence engine
 *     (messages posted to a Handler that calls `App->i(II)V`) and read by exactly one accessor,
 *     the package-private static `()S` found by [LicenseStateGetterFingerprint].
 *   - Three tiny static `()Z` predicates in one obfuscated class turn that state into verdicts:
 *       * "is licensed"   : state == 3 || state == 4
 *       * "trial expired" : Calendar.now > trialEnd && !isLicensed
 *       * "grace expired" : Calendar.now > trialEnd + 5 days && !isLicensed
 *     The first is the predicate without any `java.util.Calendar` call; the other two call
 *     Calendar and differ only in whether they consult the state accessor or the "is licensed"
 *     predicate.
 *   - The master recording switch is `is_recording_enabled && !graceExpired`, and everything else
 *     is UI (dialogs, hidden drawer entries, licence screen text).
 *
 * So four structural edits make the whole app see a verified licence, no matter what the native
 * engine or the licence server says:
 *
 *   A. the state accessor returns 3
 *   B. "is licensed" returns true
 *   C. "trial expired" returns false
 *   D. "grace expired" returns false
 *
 * A alone is sufficient for today's code because the field has exactly one reader — B..D are
 * cheap belt-and-braces in case a future build inlines the field or adds a call site. All four
 * are resolved structurally, without a single obfuscated name: package names rotate every
 * release, the Application class does not (it is named in the manifest).
 *
 * Everything fails loudly: shipping a partly patched licence is worse than shipping none.
 */
private const val STATE_LICENSED = 0x3

private fun Instruction.methodReference(): MethodReference? =
    (this as? ReferenceInstruction)?.reference as? MethodReference

private fun Method.isStaticMethod(): Boolean =
    (accessFlags and AccessFlags.STATIC.value) != 0

/** A static, argument-less `boolean` method — the shape of every licence predicate. */
private fun Method.isBooleanPredicate(): Boolean =
    isStaticMethod() && returnType == "Z" && parameterTypes.isEmpty()

private fun Method.instructionList(): List<Instruction>? =
    implementation?.instructions?.toList()

/** Same declaring class, name, return type and parameters. */
private fun MethodReference.matches(target: Method): Boolean =
    definingClass == target.definingClass &&
        name == target.name &&
        returnType == target.returnType &&
        parameterTypes.map { it.toString() } == target.parameterTypes.map { it.toString() }

private fun Method.sameShapeAs(target: Method): Boolean =
    name == target.name &&
        returnType == target.returnType &&
        parameterTypes.map { it.toString() } == target.parameterTypes.map { it.toString() }

/** Predicates that touch `java.util.Calendar` deal with trial expiry; the plain one does not. */
private fun List<Instruction>.callsCalendar(): Boolean =
    any { it.methodReference()?.definingClass == "Ljava/util/Calendar;" }

private class PredicateCandidate(
    val classDef: ClassDef,
    val method: Method,
    val instructions: List<Instruction>
)

@Suppress("unused")
val forceLicensedStatePatch = bytecodePatch(
    name = "Force licensed state",
    description = "Makes the licence accessor and every licence predicate report a verified " +
        "licence, so recording is never blocked by a trial, an expired licence or a licence " +
        "server verdict.",
    default = false
) {
    compatibleWith(COMPATIBILITY_CALLRECORDER)

    execute {
        val stateGetter = LicenseStateGetterFingerprint.method
        var stateGetterClass: ClassDef? = null

        // Every small static ()Z method in the APK. The three licence predicates are among them,
        // so collect first and decide afterwards — the scan stays single-pass and name-free.
        val candidates = ArrayList<PredicateCandidate>()
        classDefForEach { classDef ->
            if (classDef.type == stateGetter.definingClass) stateGetterClass = classDef
            classDef.methods.forEach { method ->
                if (!method.isBooleanPredicate()) return@forEach
                val instructions = method.instructionList() ?: return@forEach
                // The predicates are one-liners; anything larger is app logic that merely happens
                // to return boolean.
                if (instructions.size > 80) return@forEach
                candidates.add(PredicateCandidate(classDef, method, instructions))
            }
        }

        val getterClass = stateGetterClass
            ?: throw PatchException(
                "Application class ${stateGetter.definingClass} not found - structure changed?"
            )

        val stateUsers = candidates.filter { candidate ->
            candidate.instructions.any { it.methodReference()?.matches(stateGetter) == true }
        }
        val licensedPredicates = stateUsers.filterNot { it.instructions.callsCalendar() }
        val expiredPredicates = stateUsers.filter { it.instructions.callsCalendar() }

        if (licensedPredicates.size != 1 || expiredPredicates.size != 1) {
            throw PatchException(
                "Licence predicates: ${licensedPredicates.size} plain / " +
                    "${expiredPredicates.size} calendar, expected 1 / 1 - structure changed?"
            )
        }

        val licensedPredicate = licensedPredicates.single()
        val gracePredicates = candidates.filter { candidate ->
            candidate.instructions.callsCalendar() &&
                candidate.instructions.any {
                    it.methodReference()?.matches(licensedPredicate.method) == true
                }
        }
        if (gracePredicates.size != 1) {
            throw PatchException(
                "Grace-period predicate candidates: ${gracePredicates.size}, expected 1 - " +
                    "structure changed?"
            )
        }

        val expiredPredicate = expiredPredicates.single()
        val gracePredicate = gracePredicates.single()

        // (classDef, target method, injected smali)
        val edits = listOf(
            Triple(
                getterClass,
                stateGetter,
                "const/4 v0, 0x" + Integer.toHexString(STATE_LICENSED) + "\nreturn v0"
            ),
            Triple(licensedPredicate.classDef, licensedPredicate.method, "const/4 v0, 0x1\nreturn v0"),
            Triple(expiredPredicate.classDef, expiredPredicate.method, "const/4 v0, 0x0\nreturn v0"),
            Triple(gracePredicate.classDef, gracePredicate.method, "const/4 v0, 0x0\nreturn v0")
        )

        // Convert each class exactly once: a second `mutableClassDefBy` for the same class is how
        // perfectly good patches lose writes.
        edits.groupBy { it.first }.forEach { (classDef, classEdits) ->
            val mutable = mutableClassDefBy(classDef)
            classEdits.forEach { (_, target, body) ->
                val method = mutable.methods.firstOrNull { it.sameShapeAs(target) }
                    ?: throw PatchException(
                        "Lost ${classDef.type}->${target.name} after conversion"
                    )
                if ((method.implementation?.registerCount ?: 0) < 1) {
                    throw PatchException(
                        "${classDef.type}->${target.name} has no local register to return " +
                            "from - structure changed?"
                    )
                }
                method.addInstructions(0, body)
            }
        }

        println(
            "Force licensed state: accessor -> $STATE_LICENSED; " +
                "predicates patched (licensed=true, expired=false, grace=false)"
        )
    }
}
