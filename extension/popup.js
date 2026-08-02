const nameForm = document.getElementById("name-form");
const nameInput = document.getElementById("name");
const registered = document.getElementById("registered");
const errorEl = document.getElementById("error");

// Show either the name form or the "already registered" state,
// based on whether a name is already saved in local storage.
async function render() {
  const { name } = await chrome.storage.local.get("name");
  if (name) {
    nameForm.style.display = "none";
    registered.style.display = "flex";
  } else {
    registered.style.display = "none";
    nameForm.style.display = "block";
  }
}

nameForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  const name = nameInput.value.trim();
  if (!name) return;

  // Capture the URL of the page that is active right now, purely as a record of
  // where the name was registered — it no longer gates anything.
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const url = tab ? tab.url : null;

  errorEl.style.display = "none";

  await chrome.storage.local.set({ name, url });

  // The content script on this page picks up the saved name/URL and asks for
  // permission before the first send.
  render();
});

render();
