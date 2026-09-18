import type { ThemePreference } from '../../domain/types';
import { Icon } from '../../components/icons/Icon';
import { useAppearance } from './AppearanceProvider';

export function AppearanceControls() {
  const { preferences, update } = useAppearance();
  const themes: readonly Readonly<{ id: ThemePreference; label: string }>[] = [
    { id: 'system', label: 'System' },
    { id: 'light', label: 'Light' },
    { id: 'dark', label: 'Dark' },
  ];
  return (
    <div className="appearance-controls">
      <fieldset className="theme-choice">
        <legend>Appearance</legend>
        {themes.map((theme) => (
          <label key={theme.id} data-selected={preferences.theme === theme.id}>
            <input
              type="radio"
              name="theme"
              value={theme.id}
              checked={preferences.theme === theme.id}
              onChange={() => update({ theme: theme.id })}
            />
            <span>
              <Icon name={theme.id === 'dark' ? 'moon' : 'sun'} />
              {theme.label}
            </span>
          </label>
        ))}
      </fieldset>
      <div className="settings-toggles">
        <Toggle
          label="Increase contrast"
          detail="Strengthens boundaries and removes subtle visual effects."
          checked={preferences.increasedContrast}
          onChange={(checked) => update({ increasedContrast: checked })}
        />
        <Toggle
          label="Reduce transparency"
          detail="Uses opaque surfaces throughout PIUI."
          checked={preferences.reduceTransparency}
          onChange={(checked) => update({ reduceTransparency: checked })}
        />
        <Toggle
          label="Reduce motion"
          detail="Removes non-essential transitions and movement."
          checked={preferences.reduceMotion}
          onChange={(checked) => update({ reduceMotion: checked })}
        />
        <Toggle
          label="Accessible transcript"
          detail="Keeps the entire transcript mounted for assistive browsing."
          checked={preferences.accessibleTranscript}
          onChange={(checked) => update({ accessibleTranscript: checked })}
        />
      </div>
    </div>
  );
}

export function Toggle({
  label,
  detail,
  checked,
  onChange,
  disabled = false,
}: Readonly<{
  label: string;
  detail: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
  disabled?: boolean;
}>) {
  return (
    <label className="toggle-row" data-disabled={disabled}>
      <span>
        <strong>{label}</strong>
        <small>{detail}</small>
      </span>
      <input
        type="checkbox"
        checked={checked}
        disabled={disabled}
        onChange={(event) => onChange(event.target.checked)}
      />
      <span className="toggle-control" aria-hidden="true">
        <span />
      </span>
    </label>
  );
}
