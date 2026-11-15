package io.github.abboodan.topalencryption.ui

import android.Manifest
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.PersistableBundle
import android.content.pm.PackageManager
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.TextAutoSize
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.LocalTextStyle
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.abboodan.topalencryption.R
import io.github.abboodan.topalencryption.engine.JobState
import io.github.abboodan.topalencryption.engine.Jobs
import io.github.abboodan.topalencryption.engine.Mode
import io.github.abboodan.topalencryption.engine.Summary
import io.github.abboodan.topalencryption.update.UpdateState
import io.github.abboodan.topalencryption.update.Updater

internal val Radius = RoundedCornerShape(12.dp)
internal val SmallRadius = RoundedCornerShape(8.dp)

/** How many failures, and how many outputs, the results screen lists. */
private const val MAX_FAILURES = 50
private const val MAX_OUTPUTS = 50

@OptIn(ExperimentalComposeUiApi::class)
@Composable
fun App(model: AppViewModel, onLanguage: (String) -> Unit, onScreenshots: (Boolean) -> Unit) {
    val state by Jobs.state.collectAsStateWithLifecycle()
    val update by Updater.state.collectAsStateWithLifecycle()
    Column(
        Modifier
            .fillMaxSize()
            .background(Palette.Background)
            .windowInsetsPadding(WindowInsets.safeDrawing)
            // Lets tests and accessibility tools find elements by their tag.
            .semantics { testTagsAsResourceId = true }
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Header(onLanguage, onScreen = { model.screen = it })
        when (model.screen) {
            Screen.SETTINGS -> Settings(model, onScreenshots, onBack = { model.screen = Screen.MAIN })
            Screen.ABOUT -> About(model, update, running = state is JobState.Running, onBack = { model.screen = Screen.MAIN })
            Screen.MAIN -> when (val current = state) {
                JobState.Idle -> {
                    UpdateBanner(update) { model.screen = Screen.ABOUT }
                    Setup(model)
                }
                is JobState.Running -> Working(current)
                is JobState.Finished -> Result(current.summary, onDone = model::finish)
            }
        }
    }
}

@Composable
private fun Header(onLanguage: (String) -> Unit, onScreen: (Screen) -> Unit) {
    val other = stringResource(R.string.other_language_tag)
    var menu by remember { mutableStateOf(false) }
    Row(verticalAlignment = Alignment.CenterVertically) {
        Image(painterResource(R.drawable.logo), contentDescription = null, modifier = Modifier.size(44.dp))
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            // The name stays on one line beside the two buttons, a little smaller on a narrow screen.
            Text(
                stringResource(R.string.app_name),
                color = Palette.Text, fontWeight = FontWeight.SemiBold, maxLines = 1,
                autoSize = TextAutoSize.StepBased(minFontSize = 14.sp, maxFontSize = 19.sp, stepSize = 0.5.sp),
            )
            Text(stringResource(R.string.tagline), color = Palette.Muted, fontSize = 13.sp)
        }
        Spacer(Modifier.width(8.dp))
        SmallButton(stringResource(R.string.other_language), tag = "language") { onLanguage(other) }
        Spacer(Modifier.width(4.dp))
        Box {
            SmallButton("⋮", tag = "menu", description = stringResource(R.string.menu)) { menu = true }
            DropdownMenu(
                expanded = menu,
                onDismissRequest = { menu = false },
                containerColor = Palette.PanelHover,
                // The menu is a window of its own: its tags have to be exposed there too.
                modifier = Modifier.semantics { testTagsAsResourceId = true },
            ) {
                for ((screen, label, tag) in listOf(
                    Triple(Screen.SETTINGS, R.string.settings, "menu_settings"),
                    Triple(Screen.ABOUT, R.string.about, "menu_about"),
                )) {
                    DropdownMenuItem(
                        text = { Text(stringResource(label), color = Palette.Text, fontSize = 15.sp) },
                        onClick = {
                            menu = false
                            onScreen(screen)
                        },
                        modifier = Modifier.testTag(tag),
                    )
                }
            }
        }
    }
}

/** On the main screen, when a newer version was found or is waiting to be installed. */
@Composable
private fun UpdateBanner(update: UpdateState, onOpen: () -> Unit) {
    val text = when (update) {
        is UpdateState.Available -> stringResource(R.string.update_banner_available, update.release.version)
        is UpdateState.Ready -> stringResource(R.string.update_banner_ready, update.release.version)
        else -> return
    }
    Row(
        Modifier
            .fillMaxWidth()
            .clip(Radius)
            .background(Palette.Panel)
            .border(1.dp, Palette.Accent, Radius)
            .clickable(role = Role.Button, onClick = onOpen)
            .padding(horizontal = 16.dp, vertical = 12.dp)
            .testTag("update_banner"),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(text, color = Palette.Text, fontSize = 14.sp, modifier = Modifier.weight(1f))
        Text(stringResource(R.string.about), color = Palette.Accent, fontSize = 14.sp)
    }
}

@Composable
private fun Setup(model: AppViewModel) {
    val context = LocalContext.current
    val mode = model.mode
    val pickFiles = rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris ->
        model.add(uris.map { io.github.abboodan.topalencryption.engine.Root.Document(it) })
    }
    val pickFolder = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocumentTree()) { uri ->
        if (uri != null) model.add(listOf(io.github.abboodan.topalencryption.engine.Root.Tree(uri)))
    }
    val pickOutput = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocumentTree()) { uri ->
        if (uri != null) model.chooseOutput(uri)
    }
    // The job runs whether or not notifications are allowed; they only show its progress.
    val askNotifications = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {
        model.start()
    }

    ModeSwitch(mode, model::selectMode)

    Panel {
        val scan = model.scan
        when {
            model.roots.isEmpty() -> Muted(stringResource(if (mode == Mode.ENCRYPT) R.string.pick_encrypt else R.string.pick_open))
            model.scanning || scan == null -> Muted(stringResource(R.string.scanning))
            scan.items.isEmpty() -> Muted(stringResource(if (mode == Mode.ENCRYPT) R.string.empty_encrypt else R.string.empty_open))
            else -> {
                Text(
                    stringResource(R.string.selection_summary, context.files(scan.items.size), context.bytes(scan.totalBytes)),
                    color = Palette.Text, fontWeight = FontWeight.Medium,
                    modifier = Modifier.testTag("selection"),
                )
                val names = scan.items.take(3).joinToString("\n") { plainName(it.name) } + if (scan.items.size > 3) "\n…" else ""
                Text(names, color = Palette.Muted, fontSize = 13.sp, maxLines = 4, overflow = TextOverflow.Ellipsis)
            }
        }
        if (scan != null && scan.unreadable > 0 && !model.scanning) {
            val items = context.resources.getQuantityString(R.plurals.items, scan.unreadable, number(scan.unreadable.toLong()))
            Text(stringResource(R.string.selection_unreadable, items), color = Palette.Warn, fontSize = 13.sp)
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
            SmallButton(stringResource(R.string.add_files), tag = "add_files") { pickFiles.launch(arrayOf("*/*")) }
            SmallButton(stringResource(R.string.add_folder), tag = "add_folder") { pickFolder.launch(null) }
            if (model.roots.isNotEmpty()) {
                Spacer(Modifier.weight(1f))
                LinkButton(stringResource(R.string.clear), tag = "clear", onClick = model::clear)
            }
        }
    }

    if (mode == Mode.VERIFY) Muted(stringResource(R.string.verify_hint))
    if (mode == Mode.CHANGE) Muted(stringResource(R.string.change_hint))

    val byKey = model.byKey
    if (byKey) {
        Field(
            value = model.recoveryKey,
            onChange = { model.recoveryKey = it; model.error = null },
            label = stringResource(R.string.recovery_label),
            tag = "recovery_key",
            secret = false,
            monospace = true,
        )
    } else {
        Field(
            value = model.password,
            onChange = model::typePassword,
            label = stringResource(if (mode == Mode.CHANGE) R.string.password_current else R.string.password_label),
            tag = "password",
            secret = !model.passwordVisible,
            onToggle = { model.passwordVisible = !model.passwordVisible },
            last = mode == Mode.DECRYPT || mode == Mode.VERIFY,
        )
    }
    if (mode != Mode.ENCRYPT) {
        LinkButton(
            stringResource(if (model.useRecovery) R.string.use_password else R.string.use_recovery),
            tag = "toggle_recovery",
        ) {
            model.useRecovery = !model.useRecovery
            model.error = null
        }
    }
    if (mode == Mode.CHANGE) {
        Field(
            value = model.newPassword,
            onChange = model::typeNewPassword,
            label = stringResource(R.string.password_new),
            tag = "new_password",
            secret = !model.passwordVisible,
            // With the recovery key in use there is no other field to carry the switch.
            onToggle = if (byKey) ({ model.passwordVisible = !model.passwordVisible }) else null,
        )
    }
    if (mode == Mode.ENCRYPT || mode == Mode.CHANGE) {
        // The password the files will have from now on.
        val fresh = if (mode == Mode.CHANGE) model.newPassword else model.password
        Field(
            value = model.repeat,
            onChange = { model.repeat = it; model.error = null },
            label = stringResource(R.string.password_repeat),
            tag = "repeat",
            secret = !model.passwordVisible,
            last = true,
        )
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            SmallButton(stringResource(R.string.generate), tag = "generate", onClick = model::generate)
            if (fresh.isNotEmpty()) StrengthMeter(fresh, Modifier.weight(1f))
        }
        if (model.generated) {
            Generated(fresh)
            Text(stringResource(R.string.generated_note), color = Palette.Warn, fontSize = 13.sp)
        }
    }

    if (mode == Mode.ENCRYPT || mode == Mode.DECRYPT) {
        Panel {
            Muted(stringResource(R.string.output_label))
            Text(
                model.outputName ?: stringResource(R.string.output_default),
                color = Palette.Text, modifier = Modifier.testTag("output"),
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                SmallButton(stringResource(R.string.output_choose), tag = "output_choose") { pickOutput.launch(null) }
                if (model.outputTree != null) {
                    SmallButton(stringResource(R.string.output_reset), tag = "output_reset", onClick = model::resetOutput)
                }
            }
        }
    }

    model.error?.let { Text(stringResource(it), color = Palette.Danger, modifier = Modifier.testTag("error")) }

    val count = model.scan?.items?.size ?: 0
    val label = if (count > 0 && !model.scanning) {
        stringResource(
            when (mode) {
                Mode.ENCRYPT -> R.string.start_encrypt
                Mode.DECRYPT -> R.string.start_decrypt
                Mode.VERIFY -> R.string.start_verify
                Mode.CHANGE -> R.string.start_change
            },
            context.files(count),
        )
    } else {
        stringResource(
            when (mode) {
                Mode.ENCRYPT -> R.string.mode_encrypt
                Mode.DECRYPT -> R.string.mode_decrypt
                Mode.VERIFY -> R.string.mode_verify
                Mode.CHANGE -> R.string.mode_change
            },
        )
    }
    PrimaryButton(label, enabled = model.ready, tag = "start") {
        // Mistakes in the form are shown first; the question comes only when the job can start.
        if (model.check()) {
            if (needsNotificationQuestion(context)) {
                askNotifications.launch(Manifest.permission.POST_NOTIFICATIONS)
            } else {
                model.start()
            }
        }
    }

    if (mode == Mode.ENCRYPT) {
        val recovery = model.recovery
        if (recovery != null) {
            // The ID is shown wherever the key is used, so that a key that was swapped is noticed.
            Muted(stringResource(R.string.recovery_line_on, recovery.id), tag = "recovery_line")
        } else {
            Muted(stringResource(R.string.no_recovery), tag = "recovery_line")
        }
        LinkButton(stringResource(R.string.recovery_button), tag = "recovery_button") { model.screen = Screen.SETTINGS }
        Muted(stringResource(R.string.originals_kept))
    }
}

/** The whole generated passphrase, which is longer than the field, with a way to copy it. */
@Composable
private fun Generated(phrase: String) {
    val context = LocalContext.current
    var copied by remember(phrase) { mutableStateOf(false) }
    Panel {
        SelectionContainer {
            Text(
                phrase,
                color = Palette.Text, fontFamily = FontFamily.Monospace, fontSize = 16.sp,
                style = LocalTextStyle.current.copy(textDirection = TextDirection.Ltr),
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("generated"),
            )
        }
        SmallButton(stringResource(if (copied) R.string.copied else R.string.copy), tag = "copy") {
            val clip = ClipData.newPlainText("", phrase)
            // Keeps the passphrase out of the clipboard preview the system shows.
            clip.description.extras = PersistableBundle().apply { putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true) }
            context.getSystemService(ClipboardManager::class.java).setPrimaryClip(clip)
            copied = true
        }
    }
}

/** Asked once, the first time a job is started. */
private fun needsNotificationQuestion(context: Context): Boolean {
    if (context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED) return false
    val prefs = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
    if (prefs.getBoolean("asked_notifications", false)) return false
    prefs.edit().putBoolean("asked_notifications", true).apply()
    return true
}

@Composable
private fun Working(state: JobState.Running) {
    val context = LocalContext.current
    // Leaving with Back keeps the job running, like Home does.
    Panel {
        Text(context.working(state.mode), color = Palette.Text, fontSize = 18.sp, fontWeight = FontWeight.SemiBold)
        val known = !state.preparing && state.totalBytes > 0
        val track = Modifier
            .fillMaxWidth()
            .height(10.dp)
            .clip(RoundedCornerShape(5.dp))
            .testTag("progress")
        if (known) {
            LinearProgressIndicator(
                progress = { (state.bytes.toFloat() / state.totalBytes).coerceIn(0f, 1f) },
                modifier = track, color = Palette.Accent, trackColor = Palette.Line,
                gapSize = 0.dp, drawStopIndicator = {},
            )
        } else {
            LinearProgressIndicator(modifier = track, color = Palette.Accent, trackColor = Palette.Line, gapSize = 0.dp)
        }
        Muted(
            if (state.preparing) {
                stringResource(R.string.preparing)
            } else {
                stringResource(
                    R.string.working_detail,
                    number(state.files.toLong()), number(state.totalFiles.toLong()),
                    context.bytes(state.bytes), context.bytes(state.totalBytes),
                )
            },
            tag = "detail",
        )
    }
    SmallButton(
        stringResource(if (state.cancelling) R.string.cancelling else R.string.cancel),
        tag = "cancel", enabled = !state.cancelling, onClick = Jobs::cancel,
    )
    Muted(stringResource(R.string.working_leave))
}

@Composable
private fun Result(summary: Summary, onDone: () -> Unit) {
    val context = LocalContext.current
    BackHandler(onBack = onDone)
    val wrongPassword = summary.allFailedWith("wrong_password")
    val wrongKey = summary.allFailedWith("wrong_recovery_key")
    val (title, colour) = when {
        summary.cancelled -> R.string.result_cancelled to Palette.Warn
        wrongPassword -> R.string.result_wrong_password to Palette.Danger
        wrongKey -> R.string.result_wrong_recovery_key to Palette.Danger
        summary.failures.isNotEmpty() -> R.string.result_problems to Palette.Warn
        else -> R.string.result_all_done to Palette.Accent
    }
    Panel {
        Text(stringResource(title), color = colour, fontSize = 20.sp, fontWeight = FontWeight.SemiBold, modifier = Modifier.testTag("result_title"))
        Row(horizontalArrangement = Arrangement.spacedBy(20.dp)) {
            val doneLabel = when (summary.mode) {
                Mode.ENCRYPT -> R.string.done_encrypt
                Mode.DECRYPT -> R.string.done_decrypt
                Mode.VERIFY -> R.string.done_verify
                Mode.CHANGE -> R.string.done_change
            }
            Count(summary.done, stringResource(doneLabel), Palette.Accent, "count_done")
            Count(summary.skipped, stringResource(R.string.result_skipped), Palette.Muted, "count_skipped")
            Count(summary.failures.size, stringResource(R.string.result_failed), if (summary.failures.isEmpty()) Palette.Muted else Palette.Danger, "count_failed")
        }
        if (summary.done > 0 && summary.savedTo != null) {
            Muted(stringResource(R.string.saved_to, summary.savedTo), tag = "saved_to")
        }
        if (summary.done > 0 && summary.millis > 0 && summary.mode != Mode.CHANGE) {
            Muted(stringResource(R.string.speed, context.bytes(summary.bytes), context.duration(summary.millis)), tag = "speed")
        }
        if (summary.done > 0 && summary.recoveryId != null) {
            Muted(stringResource(R.string.result_recovery, summary.recoveryId), tag = "result_recovery")
        }
        if (wrongPassword || wrongKey) Muted(stringResource(R.string.note_wrong))
        if (summary.cancelled) Muted(stringResource(R.string.note_cancelled))
        if (summary.skipped > 0) Muted(stringResource(R.string.note_skipped))
        if (summary.installers.isNotEmpty()) {
            // Each name is isolated, so that one written right to left cannot reorder the sentence.
            val names = summary.installers.take(MAX_FAILURES).joinToString(", ") { "⁨${plainName(it)}⁩" }
            Text(
                stringResource(R.string.note_installers, names),
                color = Palette.Warn, fontSize = 14.sp, modifier = Modifier.testTag("note_installers"),
            )
        }
    }
    if (summary.outputs.isNotEmpty()) {
        val shareable = summary.outputs.filter { it.uri != null }
        val folder = remember(summary.folder) { summary.folder?.let { folderIntent(context, it) } }
        Panel {
            if (summary.outputs.size > MAX_OUTPUTS) {
                Muted(stringResource(R.string.note_first_outputs, context.files(MAX_OUTPUTS)))
            }
            for (output in summary.outputs.take(MAX_OUTPUTS)) {
                Text(plainName(output.name), color = Palette.Text, fontSize = 14.sp, modifier = Modifier.testTag("output_name"))
            }
            if (shareable.isNotEmpty() || folder != null) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (shareable.isNotEmpty()) {
                        SmallButton(stringResource(R.string.share), tag = "share") { share(context, shareable) }
                    }
                    if (folder != null) {
                        SmallButton(stringResource(R.string.open_folder), tag = "open_folder") {
                            runCatching { context.startActivity(Intent(folder)) }
                        }
                    }
                }
            }
            if (shareable.size > MAX_SHARED) {
                Muted(stringResource(R.string.note_share_first, context.files(MAX_SHARED)), tag = "note_share_first")
            }
        }
    }
    if (summary.failures.isNotEmpty() && !wrongPassword && !wrongKey) {
        Panel {
            if (summary.failures.size > MAX_FAILURES) {
                Muted(stringResource(R.string.note_first, number(MAX_FAILURES.toLong())))
            }
            for (failure in summary.failures.take(MAX_FAILURES)) {
                Column(Modifier.testTag("failure")) {
                    if (failure.name.isNotEmpty()) Text(plainName(failure.name), color = Palette.Text, fontSize = 14.sp)
                    val detail = if (failure.code == "io" && failure.detail.isNotEmpty()) " (${failure.detail})" else ""
                    Text(context.errorText(failure.code) + detail, color = Palette.Danger, fontSize = 13.sp)
                }
            }
        }
    }
    PrimaryButton(stringResource(R.string.result_again), enabled = true, tag = "done", onClick = onDone)
}

@Composable
private fun Count(value: Int, label: String, colour: Color, tag: String) {
    Column {
        Text(number(value.toLong()), color = colour, fontSize = 26.sp, fontWeight = FontWeight.SemiBold, modifier = Modifier.testTag(tag))
        Text(label, color = Palette.Muted, fontSize = 13.sp)
    }
}

@Composable
private fun ModeSwitch(mode: Mode, onSelect: (Mode) -> Unit) {
    Row(
        Modifier
            .fillMaxWidth()
            .clip(Radius)
            .background(Palette.Panel)
            .border(1.dp, Palette.Line, Radius)
            .padding(4.dp)
            // The longest label takes two lines: every tab is as tall as that one.
            .height(IntrinsicSize.Min),
        horizontalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        for ((value, label, tag) in listOf(
            Triple(Mode.ENCRYPT, R.string.mode_encrypt, "mode_encrypt"),
            Triple(Mode.DECRYPT, R.string.mode_decrypt, "mode_decrypt"),
            Triple(Mode.VERIFY, R.string.mode_verify, "mode_verify"),
            Triple(Mode.CHANGE, R.string.mode_change, "mode_change"),
        )) {
            val selected = mode == value
            Box(
                Modifier
                    .weight(1f)
                    .fillMaxHeight()
                    .clip(SmallRadius)
                    .then(if (selected) Modifier.background(Palette.AccentBrush) else Modifier)
                    .clickable(role = Role.Tab) { onSelect(value) }
                    .heightIn(min = 44.dp)
                    .padding(horizontal = 4.dp, vertical = 8.dp)
                    .testTag(tag),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    stringResource(label),
                    color = if (selected) Palette.OnAccent else Palette.Muted,
                    fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal,
                    fontSize = 14.sp, lineHeight = 17.sp, maxLines = 2, textAlign = TextAlign.Center,
                )
            }
        }
    }
}

@Composable
private fun StrengthMeter(password: String, modifier: Modifier = Modifier) {
    val level = strength(password)
    val colour = listOf(Palette.Danger, Palette.Warn, Palette.Accent2, Palette.Accent)[level - 1]
    val label = listOf(R.string.strength_1, R.string.strength_2, R.string.strength_3, R.string.strength_4)[level - 1]
    Row(modifier, verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
        Box(
            Modifier
                .weight(1f)
                .height(4.dp)
                .clip(RoundedCornerShape(2.dp))
                .background(Palette.Line),
        ) {
            Box(
                Modifier
                    .fillMaxWidth(level / 4f)
                    .height(4.dp)
                    .background(colour),
            )
        }
        Text(stringResource(label), color = colour, fontSize = 13.sp, modifier = Modifier.testTag("strength"))
    }
}

@Composable
internal fun Field(
    value: String,
    onChange: (String) -> Unit,
    label: String,
    tag: String,
    secret: Boolean,
    onToggle: (() -> Unit)? = null,
    last: Boolean = false,
    monospace: Boolean = false,
) {
    OutlinedTextField(
        value = value,
        onValueChange = onChange,
        label = { Text(label) },
        singleLine = !monospace,
        visualTransformation = if (secret) PasswordVisualTransformation() else VisualTransformation.None,
        keyboardOptions = KeyboardOptions(
            capitalization = if (monospace) KeyboardCapitalization.Characters else KeyboardCapitalization.None,
            autoCorrectEnabled = false,
            keyboardType = if (monospace) KeyboardType.Ascii else KeyboardType.Password,
            imeAction = if (last || monospace) ImeAction.Done else ImeAction.Next,
        ),
        // Passwords and keys are typed left to right in both languages.
        textStyle = MaterialTheme.typography.bodyLarge.copy(
            fontFamily = if (monospace || !secret) FontFamily.Monospace else FontFamily.Default,
            textDirection = TextDirection.Ltr,
        ),
        trailingIcon = onToggle?.let { toggle ->
            {
                LinkButton(stringResource(if (secret) R.string.show else R.string.hide), tag = "${tag}_toggle", onClick = toggle)
            }
        },
        shape = Radius,
        colors = OutlinedTextFieldDefaults.colors(
            focusedContainerColor = Palette.Panel,
            unfocusedContainerColor = Palette.Panel,
            focusedBorderColor = Palette.Accent,
            unfocusedBorderColor = Palette.Line,
            focusedLabelColor = Palette.Accent,
            unfocusedLabelColor = Palette.Muted,
            cursorColor = Palette.Accent,
            focusedTextColor = Palette.Text,
            unfocusedTextColor = Palette.Text,
        ),
        modifier = Modifier
            .fillMaxWidth()
            .testTag(tag),
    )
}

@Composable
internal fun Panel(content: @Composable ColumnScope.() -> Unit) {
    Column(
        Modifier
            .fillMaxWidth()
            .clip(Radius)
            .background(Palette.Panel)
            .border(1.dp, Palette.Line, Radius)
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
        content = content,
    )
}

@Composable
internal fun Muted(text: String, tag: String? = null) {
    Text(text, color = Palette.Muted, fontSize = 14.sp, modifier = if (tag != null) Modifier.testTag(tag) else Modifier)
}

@Composable
internal fun PrimaryButton(text: String, enabled: Boolean, tag: String, onClick: () -> Unit) {
    Box(
        Modifier
            .fillMaxWidth()
            .alpha(if (enabled) 1f else 0.45f)
            .clip(Radius)
            .background(Palette.AccentBrush)
            .clickable(enabled = enabled, role = Role.Button, onClick = onClick)
            .heightIn(min = 52.dp)
            .padding(horizontal = 16.dp, vertical = 14.dp)
            .testTag(tag),
        contentAlignment = Alignment.Center,
    ) {
        Text(text, color = Palette.OnAccent, fontSize = 16.sp, fontWeight = FontWeight.SemiBold, textAlign = TextAlign.Center)
    }
}

@Composable
internal fun SmallButton(text: String, tag: String, enabled: Boolean = true, description: String? = null, onClick: () -> Unit) {
    Box(
        Modifier
            .then(if (description != null) Modifier.semantics { contentDescription = description } else Modifier)
            .alpha(if (enabled) 1f else 0.5f)
            .clip(SmallRadius)
            .background(Palette.PanelHover)
            .border(1.dp, SolidColor(Palette.Line), SmallRadius)
            .clickable(enabled = enabled, role = Role.Button, onClick = onClick)
            .heightIn(min = 40.dp)
            .padding(horizontal = 14.dp, vertical = 9.dp)
            .testTag(tag),
        contentAlignment = Alignment.Center,
    ) {
        Text(text, color = Palette.Text, fontSize = 14.sp, maxLines = 1)
    }
}

@Composable
internal fun LinkButton(text: String, tag: String, onClick: () -> Unit) {
    Text(
        text,
        color = Palette.Accent,
        fontSize = 14.sp,
        modifier = Modifier
            .clip(SmallRadius)
            .clickable(role = Role.Button, onClick = onClick)
            .padding(horizontal = 8.dp, vertical = 8.dp)
            .testTag(tag),
    )
}
