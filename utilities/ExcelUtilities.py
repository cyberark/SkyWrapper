def get_col_widths(dataframe):
    # Taken from https://stackoverflow.com/questions/29463274/simulate-autofit-column-in-xslxwriter
    # First we find the maximum length of the index column
    idx_max = max([len(str(s)) for s in dataframe.index.values] + [len(str(dataframe.index.name))])
    # Then, we concatenate this to the max of the lengths of column name and its values for each column, left to right
    return [idx_max] + [max([len(str(s)) for s in dataframe[col].values] + [len(col)]) for col in dataframe.columns]

def set_sheet_columns_sizes(worksheet, worksheets_columns_max_size):
    for i, width in worksheets_columns_max_size[worksheet.name].items():
        worksheet.set_column(i, i, width + 2)

def set_sheet_columns_headers(sheet, columns):
    for column_index, column_name in enumerate(columns, start=0):
        sheet.write(0, column_index, column_name)