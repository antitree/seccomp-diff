from rich.table import Table
from rich.table import Row

class CustomTable(Table):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._custom_rows = []

    def add_custom_row(self, *args, **kwargs):
        row = CustomRow(*args)
        self._custom_rows.append(row)
        super().add_row(*args, **kwargs)

    def get_custom_row(self, index):
        return self._custom_rows[index]


class Cell:
    def __init__(self, text):
        self.text = text

class CustomRow(Row):
    def __init__(self, *cells, **kwargs):
        #super().__init__(*cells, **kwargs)
        self.cells = [Cell(cell) for cell in cells]

    def __getitem__(self, index):
        return self.cells[index]

    def __len__(self):
        return len(self.cells)  # Optional: for len(row)