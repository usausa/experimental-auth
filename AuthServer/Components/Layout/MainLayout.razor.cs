namespace AuthServer.Components.Layout;

using MudBlazor;

public partial class MainLayout
{
    private bool drawerOpen = true;

    private readonly MudTheme theme = new()
    {
        PaletteLight = new PaletteLight
        {
            Primary = Colors.Indigo.Default,
            Secondary = Colors.Teal.Default,
            AppbarBackground = Colors.Indigo.Darken4,
            AppbarText = Colors.Shades.White,
            DrawerBackground = Colors.Shades.White,
            Background = "#FAFAFA",
            Surface = Colors.Shades.White
        }
    };

    private void ToggleDrawer() => drawerOpen = !drawerOpen;
}
