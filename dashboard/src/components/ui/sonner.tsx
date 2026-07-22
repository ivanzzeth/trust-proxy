import { Toaster as Sonner } from 'sonner';

export function Toaster() {
  return (
    <Sonner
      theme="dark"
      position="bottom-right"
      toastOptions={{
        classNames: {
          toast:
            'group toast bg-card text-card-foreground border border-border shadow-lg rounded-md text-sm',
          description: 'text-muted-foreground',
          actionButton: 'bg-primary text-primary-foreground',
          error: 'border-destructive/40',
        },
      }}
    />
  );
}
