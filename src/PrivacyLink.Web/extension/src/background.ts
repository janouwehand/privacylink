interface ExtensionTabOptions {
  url: string;
}

interface ExtensionTabs {
  create(options: ExtensionTabOptions): void;
}

interface ExtensionAction {
  onClicked: { addListener(listener: () => void): void };
}

interface ChromeExtensionApi {
  runtime: { getURL(path: string): string };
  tabs: ExtensionTabs;
  action: ExtensionAction;
}

declare const chrome: ChromeExtensionApi;

chrome.action.onClicked.addListener(() => {
  chrome.tabs.create({
    url: chrome.runtime.getURL('index.html')
  });
});
