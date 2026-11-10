import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useId,
  useLayoutEffect,
  useRef,
  useState,
} from "react";
import { useBlocker } from "react-router-dom";

const Context = createContext(null);

function LeaveDialog({ busy, onStay, onLeave }) {
  const dialog = useRef(null);
  const stayButton = useRef(null);
  useLayoutEffect(() => {
    const element = dialog.current;
    element.showModal();
    stayButton.current.focus();
    return () => element.close();
  }, []);
  return (
    <dialog
      ref={dialog}
      className="modal leave-dialog"
      aria-labelledby="leave-title"
      aria-describedby="leave-description"
      onCancel={(event) => {
        event.preventDefault();
        onStay();
      }}
    >
      <h2 id="leave-title">
        {busy ? "저장 중입니다" : "작성 중인 내용이 있습니다"}
      </h2>
      <p id="leave-description">
        {busy
          ? "저장이 끝날 때까지 현재 화면에 머물러 주세요."
          : "이동하면 저장하지 않은 내용이 사라집니다. 계속 작성하시겠어요?"}
      </p>
      <div className="form-actions">
        <button
          type="button"
          className="button secondary"
          disabled={busy}
          onClick={onLeave}
        >
          작성 취소하고 이동
        </button>
        <button
          ref={stayButton}
          type="button"
          className="button primary"
          onClick={onStay}
        >
          {busy ? "현재 화면에 머무르기" : "계속 작성"}
        </button>
      </div>
    </dialog>
  );
}

export function UnsavedChangesProvider({ children }) {
  const registered = useRef({ owner: null, dirty: false, busy: false });
  const [snapshot, setSnapshot] = useState(registered.current);
  const [pendingAction, setPendingAction] = useState(null);
  const blocker = useBlocker(
    useCallback(
      ({ currentLocation, nextLocation }) =>
        (registered.current.dirty || registered.current.busy) &&
        (currentLocation.pathname !== nextLocation.pathname ||
          currentLocation.search !== nextLocation.search),
      [],
    ),
  );
  const blockerRef = useRef(blocker);
  blockerRef.current = blocker;
  const update = useCallback((owner, dirty, busy = false) => {
    const previous = registered.current;
    if (!dirty && !busy && previous.owner !== owner) return;
    const next = { owner, dirty, busy };
    if (
      previous.owner === owner &&
      previous.dirty === dirty &&
      previous.busy === busy
    )
      return;
    registered.current = next;
    setSnapshot(next);
  }, []);
  const clear = useCallback((owner) => {
    if (registered.current.owner !== owner) return;
    const next = { owner: null, dirty: false, busy: false };
    registered.current = next;
    setSnapshot(next);
    setPendingAction(null);
    if (blockerRef.current.state === "blocked") blockerRef.current.reset();
  }, []);
  const requestLeave = useCallback((action) => {
    if (registered.current.dirty || registered.current.busy)
      setPendingAction(() => action);
    else action();
  }, []);
  useEffect(() => {
    if (!snapshot.dirty && !snapshot.busy) return;
    const beforeUnload = (event) => {
      if (!registered.current.dirty && !registered.current.busy) return;
      event.preventDefault();
      event.returnValue = "";
    };
    window.addEventListener("beforeunload", beforeUnload);
    return () => window.removeEventListener("beforeunload", beforeUnload);
  }, [snapshot.dirty, snapshot.busy]);
  const stay = () => {
    setPendingAction(null);
    if (blocker.state === "blocked") blocker.reset();
  };
  const leave = () => {
    if (snapshot.busy) return;
    if (pendingAction) {
      const action = pendingAction;
      setPendingAction(null);
      action();
    } else if (blocker.state === "blocked") blocker.proceed();
  };
  return (
    <Context.Provider value={{ update, clear, requestLeave }}>
      {children}
      {(blocker.state === "blocked" || pendingAction) && (
        <LeaveDialog busy={snapshot.busy} onStay={stay} onLeave={leave} />
      )}
    </Context.Provider>
  );
}

export function useUnsavedChanges(dirty, busy = false) {
  const { update, clear } = useContext(Context);
  const owner = useId();
  useLayoutEffect(() => {
    update(owner, dirty, busy);
  }, [owner, dirty, busy, update]);
  useLayoutEffect(() => () => clear(owner), [owner, clear]);
  return useCallback(() => clear(owner), [owner, clear]);
}
export function useLeaveConfirmation() {
  return useContext(Context).requestLeave;
}
