const $ = (id) => document.getElementById(id);

const authView = $("authView");
const appView = $("appView");
const authForm = $("authForm");
const authMessage = $("authMessage");
const authSubmit = $("authSubmit");
const confirmWrap = $("confirmWrap");
const rememberWrap = $("rememberWrap");

const messagesEl = $("messages");
const welcome = $("welcome");
const chatList = $("chatList");
const messageInput = $("messageInput");
const fileInput = $("fileInput");
const pendingFile = $("pendingFile");

let currentUser = null;
let currentChatId = null;
let selectedFile = null;
let chats = [];
let authMode = "login";
let messages = [];

async function api(url, options = {}) {
  const response = await fetch(url, {
    credentials: "same-origin",
    ...options,
    headers: {
      ...(options.body instanceof FormData
        ? {}
        : { "Content-Type": "application/json" }),
      ...(options.headers || {})
    }
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(data.error || "درخواست ناموفق بود.");
  }

  return data;
}

function setAuthMode(mode) {
  authMode = mode;

  const isRegister = mode === "register";

  $("authSubtitle").textContent = isRegister
    ? "برای شروع، حساب خود را بسازید."
    : "به دستیار هوشمند خود خوش آمدید.";

  $("confirmWrap").classList.toggle("hidden", !isRegister);
  $("rememberWrap").classList.toggle("hidden", isRegister);

  authSubmit.textContent = isRegister ? "ساخت حساب" : "ورود";

  authMessage.textContent = "";
}

function showAuth(needsSetup) {
  authView.classList.remove("hidden");
  appView.classList.add("hidden");

  setAuthMode(needsSetup ? "register" : "login");
}

function showApp(user) {
  currentUser = user;

  authView.classList.add("hidden");
  appView.classList.remove("hidden");

  $("userLabel").textContent = "حساب: " + user.username;

  loadChats();
}

async function initialize() {
  try {
    const data = await api("/api/me");

    if (data.user) {
      showApp(data.user);
    } else {
      showAuth(data.needsSetup);
    }
  } catch (error) {
    showAuth(false);
    authMessage.textContent = error.message;
  }
}

authForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  authSubmit.disabled = true;
  authMessage.textContent = "";

  const username = $("username").value.trim();
  const password = $("password").value;

  const payload = {
    username,
    password
  };

  let endpoint = "/api/login";

  if (authMode === "register") {
    endpoint = "/api/register";
    payload.confirmPassword = $("confirmPassword").value;

    if (password !== payload.confirmPassword) {
      authMessage.textContent =
        "رمز عبور و تکرار آن یکسان نیستند.";
      authSubmit.disabled = false;
      return;
    }
  } else {
    payload.remember = $("remember").checked;
  }

  try {
    const data = await api(endpoint, {
      method: "POST",
      body: JSON.stringify(payload)
    });

    showApp(data.user);
  } catch (error) {
    authMessage.textContent = error.message;
  } finally {
    authSubmit.disabled = false;
  }
});

async function loadChats() {
  try {
    const data = await api("/api/chats");

    chats = data.chats;
    renderChatList();

    if (!currentChatId && chats.length) {
      await openChat(chats[0].id);
    } else if (!currentChatId) {
      await createChat();
    }
  } catch (error) {
    alert(error.message);
  }
}

function renderChatList() {
  chatList.replaceChildren();

  chats.forEach((chat) => {
    const row = document.createElement("div");
    row.className = "chat-item";

    const open = document.createElement("button");
    open.className = "chat-open";

    if (Number(chat.id) === Number(currentChatId)) {
      open.classList.add("active");
    }

    open.textContent = chat.title;
    open.addEventListener("click", () => openChat(chat.id));

    const remove = document.createElement("button");
    remove.className = "chat-delete";
    remove.textContent = "×";
    remove.title = "حذف گفت‌وگو";

    remove.addEventListener("click", async () => {
      if (!confirm("این گفت‌وگو حذف شود؟")) return;

      try {
        await api("/api/chats/" + chat.id, {
          method: "DELETE"
        });

        if (Number(currentChatId) === Number(chat.id)) {
          currentChatId = null;
          messages = [];
          messagesEl.replaceChildren();
        }

        await loadChats();
      } catch (error) {
        alert(error.message);
      }
    });

    row.append(open, remove);
    chatList.append(row);
  });
}

async function createChat() {
  try {
    const data = await api("/api/chats", {
      method: "POST",
      body: JSON.stringify({
        title: "گفت‌وگوی جدید"
      })
    });

    currentChatId = data.id;
    messages = [];

    renderMessages();
    await loadChats();

    closeSidebar();
  } catch (error) {
    alert(error.message);
  }
}

async function openChat(id) {
  try {
    const data = await api("/api/chats/" + id);

    currentChatId = data.chat.id;
    messages = data.chat.messages || [];

    renderMessages();
    renderChatList();

    closeSidebar();
  } catch (error) {
    alert(error.message);
  }
}

function renderMessages() {
  messagesEl.replaceChildren();

  welcome.classList.toggle("hidden", messages.length > 0);

  messages.forEach((message) => {
    const bubble = document.createElement("div");

    bubble.className =
      "message " +
      (message.role === "user" ? "user" : "assistant");

    bubble.textContent = message.content || "";

    if (message.file && message.file.url) {
      const link = document.createElement("a");

      link.href = message.file.url;
      link.textContent = "مشاهده فایل: " + message.file.name;
      link.target = "_blank";
      link.rel = "noopener noreferrer";

      bubble.append(document.createElement("br"), link);
    }

    messagesEl.append(bubble);
  });

  const conversation = $("conversation");

  conversation.scrollTop = conversation.scrollHeight;
}

async function saveMessages() {
  if (!currentChatId) return;

  const firstUserMessage = messages.find(
    (message) => message.role === "user"
  );

  const title = firstUserMessage
    ? firstUserMessage.content.slice(0, 35) || "گفت‌وگوی جدید"
    : "گفت‌وگوی جدید";

  await api("/api/chats/" + currentChatId, {
    method: "PUT",
    body: JSON.stringify({
      title,
      messages
    })
  });

  await loadChatTitlesOnly();
}

async function loadChatTitlesOnly() {
  const data = await api("/api/chats");
  chats = data.chats;
  renderChatList();
}

async function uploadSelectedFile() {
  if (!selectedFile) return null;

  const formData = new FormData();
  formData.append("file", selectedFile);

  const data = await api("/api/upload", {
    method: "POST",
    body: formData
  });

  return data.file;
}

async function sendMessage(event) {
  event.preventDefault();

  const text = messageInput.value.trim();

  if (!text && !selectedFile) return;

  $("sendBtn").disabled = true;

  let file = null;

  try {
    if (selectedFile) {
      file = await uploadSelectedFile();
    }

    const userContent = text || "فایل ارسال‌شده";

    messages.push({
      role: "user",
      content: userContent,
      file
    });

    renderMessages();

    messageInput.value = "";
    selectedFile = null;
    pendingFile.classList.add("hidden");
    fileInput.value = "";

    await saveMessages();

    const response = await api("/api/chat", {
      method: "POST",
      body: JSON.stringify({
        message: text || (
          file
            ? "فایل من در این آدرس ذخیره شده است: " + file.url +
              " . آیا امکان بررسی این فایل را داری؟"
            : ""
        )
      })
    });

    messages.push({
      role: "assistant",
      content: response.answer
    });

    renderMessages();
    await saveMessages();

  } catch (error) {
    messages.push({
      role: "assistant",
      content: "خطا: " + error.message
    });

    renderMessages();
  } finally {
    $("sendBtn").disabled = false;
    messageInput.focus();
  }
}

$("chatForm").addEventListener("submit", sendMessage);

$("attachBtn").addEventListener("click", () => {
  fileInput.click();
});

fileInput.addEventListener("change", () => {
  selectedFile = fileInput.files[0] || null;

  if (selectedFile) {
    pendingFile.textContent =
      "فایل انتخاب‌شده: " + selectedFile.name;

    pendingFile.classList.remove("hidden");
  } else {
    pendingFile.classList.add("hidden");
  }
});

$("newChat").addEventListener("click", createChat);
$("clearBtn").addEventListener("click", createChat);

document.querySelectorAll("[data-prompt]").forEach((button) => {
  button.addEventListener("click", () => {
    messageInput.value = button.dataset.prompt;
    messageInput.focus();
  });
});

$("menuBtn").addEventListener("click", () => {
  $("sidebar").classList.add("open");
  $("scrim").classList.add("show");
});

$("closeSide").addEventListener("click", closeSidebar);
$("scrim").addEventListener("click", closeSidebar);

function closeSidebar() {
  $("sidebar").classList.remove("open");
  $("scrim").classList.remove("show");
}

$("logout").addEventListener("click", async () => {
  try {
    await api("/api/logout", {
      method: "POST",
      body: JSON.stringify({})
    });

    currentUser = null;
    currentChatId = null;

    await initialize();
  } catch (error) {
    alert(error.message);
  }
});

$("changePassword").addEventListener("click", () => {
  $("changeMessage").textContent = "";
  $("changeForm").reset();
  $("passwordDialog").showModal();
});

$("cancelChange").addEventListener("click", () => {
  $("passwordDialog").close();
});

$("changeForm").addEventListener("submit", async (event) => {
  event.preventDefault();

  try {
    await api("/api/change-password", {
      method: "POST",
      body: JSON.stringify({
        oldPassword: $("oldPassword").value,
        newPassword: $("newPassword").value
      })
    });

    $("changeMessage").textContent =
      "رمز عبور با موفقیت تغییر کرد.";

    $("changeForm").reset();

    setTimeout(() => {
      $("passwordDialog").close();
    }, 1000);

  } catch (error) {
    $("changeMessage").textContent = error.message;
  }
});

initialize();
