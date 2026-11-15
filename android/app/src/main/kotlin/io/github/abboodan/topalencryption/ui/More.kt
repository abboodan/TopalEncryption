package io.github.abboodan.topalencryption.ui

import android.content.ClipData
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.DocumentsContract
import android.provider.Settings as SystemSettings
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.LocalTextStyle
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.abboodan.topalencryption.BuildConfig
import io.github.abboodan.topalencryption.R
import io.github.abboodan.topalencryption.engine.Output
import io.github.abboodan.topalencryption.engine.mimeOf
import io.github.abboodan.topalencryption.update.Problem
import io.github.abboodan.topalencryption.update.UpdateState
import io.github.abboodan.topalencryption.update.Updater

/** More files than this are not handed to another app at once. */
internal const val MAX_SHARED = 100

private const val DEVELOPER_URL = "https://github.com/abboodan"
private const val SOURCE_URL = "https://github.com/abboodan/TopalEncryption"
private const val LICENSE_URL = "https://github.com/abboodan/TopalEncryption/blob/main/LICENSE"
private const val REPORT_URL = "https://github.com/abboodan/TopalEncryption/security/advisories/new"

/**
 * Opens Android's share sheet with what a job wrote. The receiving app is given leave to
 * read exactly these files, for as long as it needs them, and nothing else.
 */
internal fun share(context: Context, outputs: List<Output>) {
    val shared = outputs.filter { it.uri != null }.take(MAX_SHARED)
    if (shared.isEmpty()) return
    val uris = ArrayList(shared.map { it.uri!! })
    // One type when they agree, a family when only that agrees ("image/*"), anything otherwise.
    val types = shared.map { mimeOf(it.name) }.distinct()
    val families = types.map { it.substringBefore('/') }.distinct()
    val type = when {
        types.size == 1 -> types[0]
        families.size == 1 -> "${families[0]}/*"
        else -> "*/*"
    }
    val send = if (uris.size == 1) {
        Intent(Intent.ACTION_SEND).putExtra(Intent.EXTRA_STREAM, uris[0])
    } else {
        Intent(Intent.ACTION_SEND_MULTIPLE).putParcelableArrayListExtra(Intent.EXTRA_STREAM, uris)
    }
    send.type = type
    // The permission to read travels with the addresses listed here.
    val clip = ClipData.newRawUri(null, uris[0])
    uris.drop(1).forEach { clip.addItem(ClipData.Item(it)) }
    send.clipData = clip
    send.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
    val chooser = Intent.createChooser(send, null)
    // Sending the results straight back to this app is never what is wanted.
    chooser.putExtra(Intent.EXTRA_EXCLUDE_COMPONENTS, arrayOf(ComponentName(context, MainActivity::class.java)))
    runCatching { context.startActivity(chooser) }
}

/** What opens [folder] in a file manager, or `null` when nothing on this phone can. */
internal fun folderIntent(context: Context, folder: Uri): Intent? {
    val view = Intent(Intent.ACTION_VIEW).setDataAndType(folder, DocumentsContract.Document.MIME_TYPE_DIR)
    return view.takeIf { it.resolveActivity(context.packageManager) != null }
}

private fun open(context: Context, url: String) {
    runCatching { context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url))) }
}

@Composable
private fun Title(text: String, onBack: () -> Unit) {
    BackHandler(onBack = onBack)
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        SmallButton(stringResource(R.string.back), tag = "back", onClick = onBack)
        Text(text, color = Palette.Text, fontSize = 20.sp, fontWeight = FontWeight.SemiBold, modifier = Modifier.testTag("title"))
    }
}

/** A setting that is on or off, with what it means underneath. */
@Composable
private fun Toggle(title: String, note: String, on: Boolean, tag: String, onChange: (Boolean) -> Unit) {
    val state = stringResource(if (on) R.string.on else R.string.off)
    Panel {
        Row(
            Modifier
                .fillMaxWidth()
                .clip(SmallRadius)
                .clickable(role = Role.Switch) { onChange(!on) }
                .semantics { stateDescription = state }
                .testTag(tag),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(title, color = Palette.Text, fontSize = 16.sp, modifier = Modifier.weight(1f))
            Spacer(Modifier.width(12.dp))
            Text(
                state,
                color = if (on) Palette.OnAccent else Palette.Muted,
                fontSize = 14.sp, fontWeight = FontWeight.SemiBold,
                modifier = Modifier
                    .clip(RoundedCornerShape(16.dp))
                    .then(if (on) Modifier.background(Palette.AccentBrush) else Modifier.background(Palette.Line))
                    .padding(horizontal = 14.dp, vertical = 6.dp)
                    .testTag("${tag}_state"),
            )
        }
        Muted(note)
    }
}

@Composable
internal fun Settings(model: AppViewModel, onScreenshots: (Boolean) -> Unit, onBack: () -> Unit) {
    Title(stringResource(R.string.settings), onBack)
    RecoveryPanel(model)
    Toggle(
        stringResource(R.string.setting_screenshots), stringResource(R.string.setting_screenshots_note),
        on = model.allowScreenshots, tag = "setting_screenshots", onChange = onScreenshots,
    )
    Toggle(
        stringResource(R.string.setting_daily), stringResource(R.string.setting_daily_note),
        on = model.dailyUpdateCheck, tag = "setting_daily", onChange = model::dailyUpdateCheck,
    )
}

/** The recovery key in use, and the way to bring one over from the PC. */
@Composable
private fun RecoveryPanel(model: AppViewModel) {
    val pickKey = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) model.importRecoveryFile(uri)
    }
    val recovery = model.recovery
    Panel {
        Text(stringResource(R.string.recovery_button), color = Palette.Text, fontSize = 16.sp, fontWeight = FontWeight.Medium)
        if (recovery != null) {
            Muted(stringResource(R.string.recovery_on))
            Muted(stringResource(R.string.recovery_id))
            SelectionContainer {
                Text(
                    recovery.id,
                    color = Palette.Accent, fontFamily = FontFamily.Monospace, fontSize = 18.sp,
                    style = LocalTextStyle.current.copy(textDirection = TextDirection.Ltr),
                    modifier = Modifier.testTag("recovery_id"),
                )
            }
            SmallButton(stringResource(R.string.recovery_remove), tag = "recovery_remove", onClick = model::removeRecovery)
            Muted(stringResource(R.string.recovery_remove_note))
        } else {
            Muted(stringResource(R.string.recovery_what))
            Muted(stringResource(R.string.recovery_where))
            Field(
                value = model.recoveryInput,
                onChange = { model.recoveryInput = it; model.recoveryError = null },
                label = stringResource(R.string.recovery_paste),
                tag = "recovery_input",
                secret = false,
                monospace = true,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                SmallButton(
                    stringResource(R.string.recovery_import), tag = "recovery_import",
                    enabled = model.recoveryInput.isNotBlank(),
                ) { model.importRecovery(model.recoveryInput) }
                SmallButton(stringResource(R.string.recovery_import_file), tag = "recovery_import_file") {
                    pickKey.launch(arrayOf("text/plain", "application/octet-stream"))
                }
            }
            Muted(stringResource(R.string.recovery_public_note))
        }
        model.recoveryError?.let {
            Text(stringResource(it), color = Palette.Danger, fontSize = 14.sp, modifier = Modifier.testTag("recovery_error"))
        }
    }
}

@Composable
internal fun About(model: AppViewModel, update: UpdateState, running: Boolean, onBack: () -> Unit) {
    val context = LocalContext.current
    Title(stringResource(R.string.about), onBack)
    Panel {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Image(painterResource(R.drawable.logo), contentDescription = null, modifier = Modifier.size(56.dp))
            Spacer(Modifier.width(14.dp))
            Column {
                Text(stringResource(R.string.app_name), color = Palette.Text, fontSize = 20.sp, fontWeight = FontWeight.SemiBold, modifier = Modifier.testTag("about_name"))
                Text(stringResource(R.string.about_version, BuildConfig.VERSION_NAME), color = Palette.Muted, fontSize = 14.sp, modifier = Modifier.testTag("about_version"))
            }
        }
        Muted(stringResource(R.string.about_description), tag = "about_description")
    }
    Panel {
        Link(stringResource(R.string.about_developer), stringResource(R.string.about_developer_name), "about_developer") { open(context, DEVELOPER_URL) }
        Link(stringResource(R.string.about_source), "github.com/abboodan/TopalEncryption", "about_source") { open(context, SOURCE_URL) }
        Link(stringResource(R.string.about_license), stringResource(R.string.about_license_name), "about_license") { open(context, LICENSE_URL) }
        LinkButton(stringResource(R.string.about_report), tag = "about_report") { open(context, REPORT_URL) }
    }
    UpdatePanel(update, running)
    Muted(stringResource(R.string.about_network), tag = "about_network")
    if (BuildConfig.PRETEND_VERSION_CODE > 0) {
        Text(
            stringResource(R.string.update_pretend, number(BuildConfig.PRETEND_VERSION_CODE.toLong())),
            color = Palette.Warn, fontSize = 13.sp, modifier = Modifier.testTag("update_pretend"),
        )
    }
}

/** A label with, beside it, what it is, which opens a web page. */
@Composable
private fun Link(label: String, value: String, tag: String, onClick: () -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text(label, color = Palette.Muted, fontSize = 14.sp, modifier = Modifier.width(110.dp))
        LinkButton(value, tag = tag, onClick = onClick)
    }
}

private fun problemText(problem: Problem): Int = when (problem) {
    Problem.NETWORK -> R.string.update_err_network
    Problem.UNEXPECTED -> R.string.update_err_unexpected
    Problem.NO_DOWNLOAD -> R.string.update_err_no_download
    Problem.TOO_LARGE -> R.string.update_err_too_large
    Problem.STORAGE -> R.string.update_err_storage
    Problem.NOT_AN_APP -> R.string.update_err_not_an_app
    Problem.WRONG_APP -> R.string.update_err_wrong_app
    Problem.NOT_NEWER -> R.string.update_err_not_newer
    Problem.WRONG_SIGNATURE -> R.string.update_err_wrong_signature
    Problem.INSTALL -> R.string.update_err_install
}

/** Looking for a new version, downloading it, and handing it to Android's installer. */
@Composable
private fun UpdatePanel(update: UpdateState, running: Boolean) {
    val context = LocalContext.current
    // Set when Install found that Android has not been told the app may install its update.
    var askedToAllow by remember { mutableStateOf(false) }
    Panel {
        when (update) {
            UpdateState.Idle -> {}
            UpdateState.Checking -> Muted(stringResource(R.string.update_checking), tag = "update_status")
            is UpdateState.UpToDate -> Muted(stringResource(R.string.update_latest), tag = "update_status")
            is UpdateState.Available -> {
                val release = update.release
                Text(
                    if (release.size > 0) {
                        stringResource(R.string.update_available, release.version, context.bytes(release.size))
                    } else {
                        stringResource(R.string.update_available_plain, release.version)
                    },
                    color = Palette.Text, modifier = Modifier.testTag("update_status"),
                )
                SmallButton(stringResource(R.string.update_download), tag = "update_download", enabled = !running) {
                    Updater.download(context)
                }
                if (running) Muted(stringResource(R.string.update_busy), tag = "update_busy")
            }
            is UpdateState.Downloading -> {
                Text(stringResource(R.string.update_downloading, update.release.version), color = Palette.Text, modifier = Modifier.testTag("update_status"))
                val track = Modifier
                    .fillMaxWidth()
                    .height(10.dp)
                    .clip(RoundedCornerShape(5.dp))
                    .testTag("update_progress")
                if (update.total > 0) {
                    LinearProgressIndicator(
                        progress = { (update.bytes.toFloat() / update.total).coerceIn(0f, 1f) },
                        modifier = track, color = Palette.Accent, trackColor = Palette.Line,
                        gapSize = 0.dp, drawStopIndicator = {},
                    )
                    Muted(stringResource(R.string.update_progress, context.bytes(update.bytes), context.bytes(update.total)), tag = "update_detail")
                } else {
                    LinearProgressIndicator(modifier = track, color = Palette.Accent, trackColor = Palette.Line, gapSize = 0.dp)
                    Muted(context.bytes(update.bytes), tag = "update_detail")
                }
                SmallButton(stringResource(R.string.cancel), tag = "update_cancel", onClick = Updater::cancel)
            }
            is UpdateState.Verifying -> Muted(stringResource(R.string.update_verifying), tag = "update_status")
            is UpdateState.Ready -> {
                Text(stringResource(R.string.update_ready, update.release.version), color = Palette.Text, modifier = Modifier.testTag("update_status"))
                update.problem?.let { problem ->
                    val detail = if (update.detail.isNotEmpty()) " (${update.detail})" else ""
                    Text(stringResource(problemText(problem)) + detail, color = Palette.Danger, fontSize = 14.sp, modifier = Modifier.testTag("update_error"))
                }
                SmallButton(stringResource(R.string.update_install), tag = "update_install", enabled = !running) {
                    if (context.packageManager.canRequestPackageInstalls()) {
                        askedToAllow = false
                        Updater.install(context)
                    } else {
                        // Android's own switch for this app; the user comes back and presses Install again.
                        askedToAllow = true
                        val allow = Intent(SystemSettings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:${context.packageName}"))
                        runCatching { context.startActivity(allow) }
                    }
                }
                if (askedToAllow) Text(stringResource(R.string.update_allow), color = Palette.Warn, fontSize = 14.sp, modifier = Modifier.testTag("update_allow"))
                if (running) Muted(stringResource(R.string.update_busy), tag = "update_busy")
            }
            is UpdateState.Installing -> Muted(stringResource(R.string.update_installing), tag = "update_status")
            is UpdateState.Failed -> {
                // What GitHub or the network said is shown as it is: it helps when reporting a problem.
                val detail = if (update.problem == Problem.NETWORK || update.detail.isEmpty()) "" else " (${update.detail})"
                Text(stringResource(problemText(update.problem)) + detail, color = Palette.Danger, fontSize = 14.sp, modifier = Modifier.testTag("update_error"))
            }
        }
        val canCheck = update == UpdateState.Idle || update is UpdateState.UpToDate || update is UpdateState.Failed
        if (canCheck || update == UpdateState.Checking) {
            SmallButton(stringResource(R.string.check_updates), tag = "check_updates", enabled = canCheck) {
                Updater.dismiss()
                Updater.check(context)
            }
        }
    }
}
