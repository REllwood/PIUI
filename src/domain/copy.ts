// Counts in interface copy read naturally in the singular too: "1 addition", never
// "1 additions". Pass the plural when it is not the singular plus "s".
export function countLabel(count: number, singular: string, plural = `${singular}s`): string {
  return `${count} ${count === 1 ? singular : plural}`;
}
