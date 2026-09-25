import { useEffect, useId, useMemo, useRef, useState } from 'react';
import { useProduct } from '../../app/ProductContext';
import { Icon } from '../../components/icons/Icon';
import { LoadingLabel } from '../../components/primitives/LoadingLabel';
import { isTurnActive } from '../../domain/machines';
import './model-picker.css';

const thinkingOptions = [
  { value: 'off', label: 'Off', detail: 'Respond without extended thinking.' },
  { value: 'minimal', label: 'Minimal', detail: 'A little thinking for straightforward tasks.' },
  { value: 'low', label: 'Quick', detail: 'Keep thinking brief for everyday questions.' },
  { value: 'medium', label: 'Balanced', detail: 'A balance of depth and response time.' },
  { value: 'high', label: 'Deep', detail: 'Spend more time on complex changes and decisions.' },
  { value: 'xhigh', label: 'Extended', detail: 'The most thinking time for demanding work.' },
] as const;

type ThinkingLevel = (typeof thinkingOptions)[number]['value'];

function thinkingLevel(value: unknown): ThinkingLevel {
  return thinkingOptions.find((option) => option.value === value)?.value ?? 'medium';
}

export function ModelPicker() {
  const product = useProduct();
  const { snapshot, settings } = product;
  const dialogRef = useRef<HTMLDialogElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const searchRef = useRef<HTMLInputElement>(null);
  const mountedRef = useRef(true);
  const savingRef = useRef(false);
  const restoreFocusRef = useRef(false);
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [providerId, setProviderId] = useState('');
  const [modelId, setModelId] = useState('');
  const [thinking, setThinking] = useState<ThinkingLevel>('medium');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const titleId = useId();
  const descriptionId = useId();
  const thinkingDescriptionId = useId();
  const radioGroupName = useId();
  const providerSetting = settings.find((setting) => setting.key === 'model.provider');
  const modelSetting = settings.find((setting) => setting.key === 'model.id');
  const thinkingSetting = settings.find((setting) => setting.key === 'reasoning.level');
  const currentProvider = snapshot.providers.find(
    (provider) => provider.id === providerSetting?.value,
  );
  const currentModel = currentProvider?.models.find((model) => model.id === modelSetting?.value);
  const currentThinking = thinkingOptions.find(
    (option) => option.value === thinkingLevel(thinkingSetting?.value),
  );
  const selectedProvider = snapshot.providers.find(
    (provider) => provider.connected && provider.id === providerId,
  );
  const selectedModel = selectedProvider?.models.find((model) => model.id === modelId);
  const turnActive = isTurnActive(snapshot.turnStatus);
  const busy = saving || product.activeOperation !== null || turnActive;
  const connectedProviders = snapshot.providers.filter(
    (provider) => provider.connected && provider.models.length > 0,
  );
  const groups = useMemo(() => {
    const search = query.trim().toLocaleLowerCase('en-AU');
    return snapshot.providers
      .filter((provider) => provider.connected)
      .map((provider) => ({
        ...provider,
        models: provider.models.filter((model) =>
          `${provider.name} ${model.name} ${model.id}`.toLocaleLowerCase('en-AU').includes(search),
        ),
      }))
      .filter((provider) => provider.models.length > 0);
  }, [snapshot.providers, query]);
  const canSave = Boolean(
    !busy && selectedModel && snapshot.activeSessionId && providerSetting && modelSetting,
  );
  const changed =
    providerId !== providerSetting?.value ||
    modelId !== modelSetting?.value ||
    Boolean(selectedModel?.reasoning && thinkingSetting && thinking !== thinkingSetting.value);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;
    if (open && !dialog.open) {
      dialog.showModal();
      searchRef.current?.focus();
    } else if (!open && dialog.open) {
      dialog.close();
    }
  }, [open]);

  useEffect(() => {
    if (!open && !busy && restoreFocusRef.current) {
      triggerRef.current?.focus();
      restoreFocusRef.current = false;
    }
  }, [open, busy]);

  const close = () => {
    if (savingRef.current) return;
    restoreFocusRef.current = true;
    setOpen(false);
    dialogRef.current?.close();
    triggerRef.current?.focus();
  };

  const show = () => {
    if (busy) return;
    restoreFocusRef.current = false;
    setProviderId(typeof providerSetting?.value === 'string' ? providerSetting.value : '');
    setModelId(typeof modelSetting?.value === 'string' ? modelSetting.value : '');
    setThinking(thinkingLevel(thinkingSetting?.value));
    setQuery('');
    setError(null);
    setOpen(true);
  };

  const save = async () => {
    if (!canSave || savingRef.current || !selectedModel) return;
    if (!changed) {
      close();
      return;
    }
    const values: Readonly<Record<string, unknown>> = {
      'model.provider': providerId,
      'model.id': modelId,
      ...(selectedModel.reasoning && thinkingSetting ? { 'reasoning.level': thinking } : {}),
    };
    const changes = settings
      .filter(
        (setting) => Object.hasOwn(values, setting.key) && setting.value !== values[setting.key],
      )
      .map((setting) => ({
        key: setting.key,
        value: values[setting.key],
        scope: setting.scope,
        expectedRevision: setting.revision,
      }));
    savingRef.current = true;
    setSaving(true);
    setError(null);
    try {
      await product.saveSettings(changes);
      if (mountedRef.current) {
        savingRef.current = false;
        close();
      }
    } catch {
      if (mountedRef.current) {
        setError('Your choice could not be fully saved. Review it and try again.');
      }
    } finally {
      savingRef.current = false;
      if (mountedRef.current) setSaving(false);
    }
  };

  const manageProviders = () => {
    close();
    product.openSettings('providers');
  };

  return (
    <div className="model-picker">
      <button
        ref={triggerRef}
        type="button"
        className="model-picker__trigger"
        aria-haspopup="dialog"
        aria-expanded={open}
        aria-label={
          currentModel
            ? `Choose model: ${currentModel.name}${currentModel.reasoning ? `, ${currentThinking?.label} thinking` : ''}`
            : 'Choose a model'
        }
        disabled={busy}
        title={
          turnActive
            ? 'You can change models when Pi finishes this turn.'
            : 'Choose model and thinking'
        }
        onClick={show}
      >
        <span className="model-picker__trigger-name">{currentModel?.name ?? 'Choose a model'}</span>
        {currentModel?.reasoning && (
          <span className="model-picker__trigger-thinking">{currentThinking?.label} thinking</span>
        )}
        <Icon name="chevron-down" width={14} height={14} />
      </button>
      <dialog
        ref={dialogRef}
        className="model-picker__dialog"
        aria-labelledby={titleId}
        aria-describedby={descriptionId}
        aria-busy={saving}
        onCancel={(event) => {
          event.preventDefault();
          close();
        }}
        onClose={() => {
          setOpen(false);
          if (triggerRef.current && !triggerRef.current.disabled) {
            triggerRef.current.focus();
            restoreFocusRef.current = false;
          }
        }}
        onKeyDown={(event) => {
          // Inputs belong to the composer form; Enter here must not send its draft.
          if (event.key === 'Enter' && event.target instanceof HTMLInputElement) {
            event.preventDefault();
          }
          if (event.key === 'Tab') {
            const controls = Array.from(
              event.currentTarget.querySelectorAll<HTMLElement>(
                'button, input, select, textarea, a[href], [tabindex]',
              ),
            ).filter(
              (control) =>
                control.tabIndex >= 0 &&
                !control.matches(':disabled') &&
                control.getClientRects().length > 0,
            );
            const first = controls[0];
            const last = controls.at(-1);
            if (event.shiftKey && document.activeElement === first) {
              event.preventDefault();
              last?.focus();
            } else if (!event.shiftKey && document.activeElement === last) {
              event.preventDefault();
              first?.focus();
            }
          }
        }}
        onPointerDown={(event) => {
          if (event.target !== event.currentTarget) return;
          const bounds = event.currentTarget.getBoundingClientRect();
          if (
            event.clientX < bounds.left ||
            event.clientX > bounds.right ||
            event.clientY < bounds.top ||
            event.clientY > bounds.bottom
          )
            close();
        }}
      >
        <div className="model-picker__heading">
          <div>
            <h2 id={titleId}>Choose your model</h2>
            <p id={descriptionId}>The model and thinking Pi will use for your next message.</p>
          </div>
          <button
            type="button"
            className="icon-button"
            aria-label="Close model picker"
            disabled={saving}
            onClick={close}
          >
            <Icon name="close" width={18} height={18} />
          </button>
        </div>
        {connectedProviders.length > 0 ? (
          <>
            <label className="model-picker__search">
              <Icon name="search" width={18} height={18} />
              <span className="sr-only">Search models</span>
              <input
                ref={searchRef}
                type="search"
                placeholder="Find a model…"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                disabled={saving}
                autoComplete="off"
                spellCheck={false}
              />
            </label>
            <fieldset className="model-picker__models" disabled={busy}>
              <legend className="sr-only">Available models</legend>
              {groups.map((provider) => (
                <div className="model-picker__provider" key={provider.id}>
                  <h3>{provider.name}</h3>
                  {provider.models.map((model) => {
                    const selected = model.id === modelId && provider.id === providerId;
                    return (
                      <label
                        className="model-picker__option"
                        data-selected={selected}
                        key={model.id}
                      >
                        <input
                          type="radio"
                          name={radioGroupName}
                          value={JSON.stringify([provider.id, model.id])}
                          checked={selected}
                          onChange={() => {
                            setProviderId(provider.id);
                            setModelId(model.id);
                            setError(null);
                          }}
                        />
                        <span className="model-picker__option-copy">
                          <span className="model-picker__option-name">{model.name}</span>
                          <span className="model-picker__option-detail">
                            {model.reasoning ? 'Adjustable thinking' : 'Direct responses'}
                            {model.acceptsImages ? ' · Supports images' : ''}
                          </span>
                        </span>
                        {selected && <Icon name="check" width={18} height={18} />}
                      </label>
                    );
                  })}
                </div>
              ))}
              {groups.length === 0 && (
                <p className="model-picker__empty" role="status">
                  No models match “{query}”. Try a model or provider name.
                </p>
              )}
            </fieldset>
            {selectedModel?.reasoning && (
              <div className="model-picker__thinking">
                <label>
                  <span>Thinking</span>
                  <select
                    aria-label="Thinking"
                    className="select"
                    value={thinking}
                    onChange={(event) => {
                      setThinking(thinkingLevel(event.target.value));
                      setError(null);
                    }}
                    disabled={busy || !thinkingSetting}
                    aria-describedby={thinkingDescriptionId}
                  >
                    {thinkingOptions.map((option) => (
                      <option key={option.value} value={option.value}>
                        {option.label}
                      </option>
                    ))}
                  </select>
                </label>
                <p id={thinkingDescriptionId}>
                  {thinkingOptions.find((option) => option.value === thinking)?.detail} Availability
                  depends on the model.
                </p>
              </div>
            )}
            {(!snapshot.activeSessionId || !providerSetting || !modelSetting) && (
              <p className="model-picker__notice" role="status">
                Start a connected conversation to change its model.
              </p>
            )}
            {turnActive && (
              <p className="model-picker__notice" role="status">
                Pi is working. You can change models when this turn finishes.
              </p>
            )}
          </>
        ) : (
          <div className="model-picker__empty">
            <p>Connect a provider to choose from its available models.</p>
            <p>You can use a supported subscription or your own API key.</p>
          </div>
        )}
        {error && (
          <p className="model-picker__error" role="alert">
            {error}
          </p>
        )}
        <div className="model-picker__footer">
          <button
            type="button"
            className="button button--quiet"
            onClick={manageProviders}
            disabled={busy}
          >
            {connectedProviders.length > 0 ? 'Manage providers' : 'Connect a provider'}
          </button>
          {connectedProviders.length > 0 && (
            <button
              type="button"
              className="button button--primary"
              disabled={!canSave}
              onClick={() => void save()}
            >
              {saving ? <LoadingLabel>Saving…</LoadingLabel> : changed ? 'Save choice' : 'Done'}
            </button>
          )}
        </div>
      </dialog>
    </div>
  );
}
