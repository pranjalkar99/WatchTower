"use client";

import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { fetchChatMessages, fetchDashboard, WS_URL } from "@/lib/api";
import type { ChatMessage, DashboardState } from "@/lib/types";

interface DashboardContextValue {
  state: DashboardState | null;
  connected: boolean;
  chatMessages: ChatMessage[];
  isTyping: boolean;
  refresh: () => Promise<void>;
}

const DashboardContext = createContext<DashboardContextValue>({
  state: null,
  connected: false,
  chatMessages: [],
  isTyping: false,
  refresh: async () => {},
});

export function DashboardProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<DashboardState | null>(null);
  const [connected, setConnected] = useState(false);
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
  const [isTyping, setIsTyping] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const [data, chat] = await Promise.all([fetchDashboard(), fetchChatMessages()]);
      setState(data);
      setChatMessages(chat.messages ?? data.chat_messages ?? []);
    } catch {
      /* backend may not be up yet */
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  useEffect(() => {
    let ws: WebSocket | null = null;
    let retryTimer: ReturnType<typeof setTimeout>;

    const connect = () => {
      ws = new WebSocket(WS_URL);

      ws.onopen = () => setConnected(true);
      ws.onclose = () => {
        setConnected(false);
        retryTimer = setTimeout(connect, 2000);
      };
      ws.onerror = () => ws?.close();
      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          if (msg.type === "state_update" && msg.data) {
            setState(msg.data);
            if (msg.data.chat_messages) {
              setChatMessages(msg.data.chat_messages);
            }
          } else if (msg.type === "chat_history" && msg.data) {
            setChatMessages(msg.data);
          } else if (msg.type === "chat_message" && msg.data) {
            setIsTyping(false);
            setChatMessages((prev) => {
              if (prev.some((m) => m.id === msg.data.id)) return prev;
              return [...prev, msg.data];
            });
          } else if (msg.type === "chat_typing") {
            setIsTyping(Boolean(msg.typing));
          } else if (msg.type === "chat_clear") {
            setChatMessages([]);
            setIsTyping(false);
          }
        } catch {
          /* ignore */
        }
      };
    };

    connect();
    return () => {
      clearTimeout(retryTimer);
      ws?.close();
    };
  }, []);

  return (
    <DashboardContext.Provider value={{ state, connected, chatMessages, isTyping, refresh }}>
      {children}
    </DashboardContext.Provider>
  );
}

export function useDashboard() {
  return useContext(DashboardContext);
}
