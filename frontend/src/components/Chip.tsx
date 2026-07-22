import type { InputHTMLAttributes, ReactNode } from 'react';

interface ChipProps extends Omit<InputHTMLAttributes<HTMLInputElement>, 'type'> {
  children: ReactNode;
  active: boolean;
  icon?: ReactNode;
}

export function Chip({ children, active, icon, ...rest }: ChipProps) {
  return (
    <label className={`chip${active ? ' active' : ''}`}>
      <input type="checkbox" checked={active} {...rest} />
      {icon}
      {children}
   </label>
  );
}
