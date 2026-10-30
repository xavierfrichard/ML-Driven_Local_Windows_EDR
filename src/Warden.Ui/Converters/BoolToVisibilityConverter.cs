using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace Warden.Ui.Converters;

/// <summary>
/// Converts a boolean value to a Visibility value.
/// True -> Visible, False -> Collapsed
/// </summary>
[ValueConversion(typeof(bool), typeof(Visibility))]
public sealed class BoolToVisibilityConverter : IValueConverter
{
    /// <summary>
    /// Gets or sets whether to use Hidden instead of Collapsed for false values.
    /// </summary>
    public bool UseHidden { get; set; } = false;

    /// <summary>
    /// Gets or sets whether to invert the conversion (true -> Collapsed/Hidden, false -> Visible).
    /// </summary>
    public bool Invert { get; set; } = false;

    /// <summary>
    /// Converts a boolean value to Visibility.
    /// </summary>
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        bool boolValue = value is bool b && b;
        
        // Check for invert
        if (Invert)
        {
            boolValue = !boolValue;
        }

        return boolValue ? Visibility.Visible : (UseHidden ? Visibility.Hidden : Visibility.Collapsed);
    }

    /// <summary>
    /// Converts Visibility back to boolean.
    /// </summary>
    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is Visibility visibility)
        {
            bool result = visibility == Visibility.Visible;
            return Invert ? !result : result;
        }
        return false;
    }
}
